# Compact mainnet proof worker source

This is the complete assembled source of the qualified compact worker, extended
with the pinned mainnet statement domain and height checks. It no longer needs
private research directories or a separately reconstructed source overlay.
`BASELINE-SOURCE.json` identifies its published v0.5.2 baseline and source hashes.

The shared opening reduction and its verifier come directly from this checkout's
`cmfd-consensus`. GPU proving explicitly binds evaluations before its trusted
builder interface samples a challenge; CPU acceptance independently calls the
backend's untrusted-evaluations verifier. The parameters remain blowup 1,
270 queries, 16 grinding bits and six commitments.

On native Linux x86-64, install CUDA 12.9.1, Rust 1.97.1, CMake 4.4, GCC/G++,
and the legacy NVTX library. Prepare the pinned SP1 and CUTLASS checkouts using
`../production-v4-prover/prepare-dependencies.sh` on a fresh build machine.
That helper refuses to overwrite existing dependencies. The build verifies the
exact SP1 revision and patch before compiling. Set `CMFD_CUDA_ROOT` to the CUDA
toolkit directory, `CMFD_GPU_TARGET_DIR` to a separate absolute build directory,
and `CMFD_BUILD_SOURCE_COMMIT` to the frozen release commit, then run `build.sh`.

The output is the isolated CUDA worker. Pair it with the checked-in
`../compact-multigpu/coordinator.py` and wrapper as
`cmfd-direct-multigpu-worker` and `cmfd-direct-multigpu-prover`. Mainnet pools
start the height-aware `packaging/compact-proof-mainnet/fork-prover.py` router;
they do not invoke the compact worker as a legacy single-GPU prover.

The manifest contains the public SDK's canonical `/root` build locations used
by the dependency preparation helper. Model banks and fixed artifacts are
downloaded separately and authenticated against the unchanged signed manifest.
