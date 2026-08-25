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
confirms the `compute_70` PTX fallback, and runs a 128-nonce CPU/CUDA
differential test. It also emits an identity-only `.build-receipt`; this receipt
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
