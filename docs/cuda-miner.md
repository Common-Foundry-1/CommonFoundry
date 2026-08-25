# ForgeMatrix v2 CUDA miner

This optional backend accelerates the exact tiny ForgeMatrix-v2 relation used
by the valueless Common Foundry Devnet-0. It works in both **Solo** and **Pool**
mode in the desktop wallet. If the library is absent, the wallet uses the CPU
reference evaluator.

It is not the production 6 GiB model, succinct prover, or evidence that model
bytes physically occupied VRAM. Mainnet remains disabled.

## Supported NVIDIA generations

The packaged fat library contains native CUDA images for:

| Architecture | CUDA target | Representative cards |
| --- | --- | --- |
| Volta | `sm_70` | Tesla V100, Titan V, Quadro GV100 |
| RTX 20 series (Turing) | `sm_75` | RTX 2060 through RTX 2080 Ti |
| RTX 30 series (Ampere) | `sm_86` | RTX 3060 through RTX 3090 Ti |
| RTX 40 series (Ada) | `sm_89` | RTX 4060 through RTX 4090 |
| RTX 50 series (Blackwell) | `sm_120` | RTX 5060 through RTX 5090 |

A `compute_70` PTX image is also included as a forward-compatible fallback.
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
- 524,288 activation bytes and 6,442,450,944 resident weight bytes;
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

Weights remain resident and are transposed once at finalization. Each real
layer then uses exact signed `INT8 x INT8 -> INT32` DP4A accumulation, the same
coordinate mask, the 134,217,689 transition-field cubic, and reduction modulo
251 as Rust. There is no dummy power loop. The implementation is self-contained
in the existing static-runtime DLL and retains the Volta-through-Blackwell
targets; it does not introduce a cuBLAS installation requirement.

The qualification seam runs the same transpose, DP4A, mask, cubic, and output
encoding code without activating production consensus:

```powershell
$env:CMFD_CUDA_MINER_LIBRARY = '<absolute-path-to-cmfd-forgematrix-v2-miner.dll>'
cargo run --release -p cmfd-cuda --example production_differential
```

On August 25, 2026, an RTX 5090 (driver 610.88, compute capability 12.0) with a
CUDA 12.9.86 build matched Rust byte-for-byte on both vectors:

| Vector | Values | BLAKE3 output digest | GPU time |
| --- | ---: | --- | ---: |
| Dense 4 x 32 | 128 | `bd24f76f7269c861b72d904240d5a862233a4dd759564cf1e0c5811326e2ece5` | 187.471 ms |
| One full 128 x 4,096 layer | 524,288 | `36661181f19654dc9d8f40bccf296372e511fb48aff18cba05762c28553e08bd` | 44.481 ms |

Those timings include qualification allocation, upload, and weight transpose;
they are not steady-state hashrate. A separate zero-centered synthetic canary
allocated the complete 6.44 GB geometry, uploaded all three banks, traversed all
384 layers, and matched its analytical all-zero 524,288-byte output. Allocation
took 0.170 seconds, upload 0.430 seconds, one-time transpose 0.013 seconds, and
one complete nonce evaluation 14.934 seconds. The canary proves control-flow and
shape correctness, not the identity or output of the ceremony model. At roughly
0.067 nonces per second, this first self-contained DP4A path is a correctness
baseline; architecture-specific tensor-core work is still needed before its
performance can represent an RC.

A complete authenticated 384-layer ceremony-model run and winning-nonce proof
also remain required before this path can be selected or described as a
production release candidate.

## Build on Windows

Requirements:

- NVIDIA CUDA Toolkit 12.8 or 12.9;
- Visual Studio 2022 C++ Build Tools;
- CMake and Ninja;
- the Rust toolchain used by the repository.

From the repository root:

```powershell
$releaseCommit = '<full-lowercase-release-commit>'
.\scripts\build-cuda-miner.ps1 -ExpectedCommit $releaseCommit
```

The script builds `target\gpu-miner-build\cmfd-forgematrix-v2-miner.dll`,
checks for native `sm_70`, `sm_75`, `sm_86`, `sm_89`, and `sm_120` images,
confirms the `compute_70` PTX fallback, runs the Devnet CPU/CUDA differential,
and then runs the dense and production-geometry Rust/CUDA vectors above. It
also emits an identity-only `.build-receipt`; this receipt
detects mixed inputs but is not a signature or authenticated build attestation.

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
