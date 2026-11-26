# CPU share verification and compact proving

Stefan and AriaPool created the original CPU share verifier, CPU compact prover, AVX-512 VNNI replay kernel, and pool integration. Common Foundry contributed the subsequent replay kernel, commitment, opening, and CPU placement optimizations. The contribution history is in CREDITS.md.

## Requirements

Use a production-mainnet node with its authenticated MODEL-V2.bank, fixed artifact record, tree files, and row-major codewords. The standalone prover requires an x86-64 CPU with AVX-512F, AVX-512BW, and AVX-512 VNNI. Build from this directory on the target CPU with Cargo's pinned lockfile and the supplied target-cpu=native configuration.

    cargo build --release --locked

## Native Windows pool on Ryzen 9 9950X3D

The supplied start-cpu-pool.ps1 launcher locks the model and sets this profile. Use the default streamed work bank to share the authenticated file cache. For direct node startup, set the following in the pool process environment before launching the candidate node with the normal mainnet model, fixed record and pool configuration. Use absolute paths. The profile starts the prover executable directly.

    ARIA_POOL_CPU_ONLY=1
    CMFD_CPU_POOL_PROFILE=9950x3d
    ARIA_POOL_CPU_PROVER=D:\CommonFoundry\aria-cmfd-cpu-prover.exe
    ARIA_POOL_CPU_PROVER_SCRATCH=D:\CommonFoundry\cpu-proof-scratch
    ARIA_POOL_CPU_SHARES=1x14

CPU-only mode requires the GPU pool worker options to be omitted. The Windows profile checks the CPU model, sixteen physical cores, SMT topology, and the process's allowed CPU mask. Replay uses one logical processor on each of the first fourteen physical cores. Each active share check restricts the external prover to the other two physical cores. At the end of the check, the pool restores the prover's full processor mask. The pool and the bundled prover share two 1.5 GiB trace buffers. The pool retains the winning trace until its proof completes and can check the next share in the other buffer. The prover checks the trace against the winning work digest and uses 28 Rayon workers. The first proof includes cold allocations.

## Linux trace reuse

Set `CMFD_CPU_TRACE_REUSE=1` in the Linux pool environment and use the matching CPU prover. The bundled `run-cpu-prover` launcher preserves the two inherited read-only file descriptors through exec. Pool and worker use sealed anonymous memory files for the two 1.5 GiB trace slots. The kernel must support memfd sealing including F_SEAL_FUTURE_WRITE, and procfs must be mounted. The pool owns the writable views and retains each winning trace until the proof is returned. The worker checks the trace against the replayed work digest. Linux uses its normal scheduler and the configured replay and Rayon thread counts.

## Linux and manual pool configuration

For CPU-only operation, set ARIA_POOL_CPU_ONLY=1 and ARIA_POOL_CPU_PROVER to the absolute path of a launcher that starts the prover with --server MODEL RECORD THREADS. See run-prover.sh.example. ARIA_POOL_CPU_SHARES=1x8 allows one replay at a time with eight threads. ARIA_POOL_CPU_PROVER_TIMEOUT_S sets the request timeout in seconds. ARIA_POOL_CPU_PROVER_SCRATCH selects the writable, private directory for temporary proof and template files. Use an account-owned directory. The qualified Linux run used ARIA_POOL_CPU_SHARES=1x14, CMFD_CPU_TRACE_REUSE=1, CMFD_CPU_TRACE_THREADS=16 and RAYON_NUM_THREADS=28. The measured Windows placement profile is platform-specific.

Hybrid pools can enable ARIA_POOL_CPU_SHARES while retaining their configured GPU proof path. Adding ARIA_POOL_CPU_PROVER selects the CPU proof worker with the existing GPU fallback. The pool passes proof packets through the normal mainnet consensus checks.

## Standalone prover

    aria-cmfd-cpu-prover --server MODEL RECORD THREADS
    aria-cmfd-cpu-prover MODEL RECORD THREADS TEMPLATE OUTPUT

Server commands use the existing tab-separated RUN protocol. ARIA_PROVER_WARMUP_TEMPLATE selects a frozen template for startup warm-up. ARIA_PROVER_NO_WARMUP=1 skips the warm-up. ARIA_PROVER_SELF_CHECK=1 enables full worker-side verification. A pool upgrading an existing node should back up its data, ledger and configuration before switching executables.

## Qualification

The Linux release worker on a Ryzen 9 9950X3D under WSL2 produced five timed proofs at a median of 5.77 s. On native Windows the separately qualified pair produced a 5.93 s median. The five-minute CPU-only runs used simulated share arrivals, recorded mainnet job changes and a locked model. Both runs checked 54 ordinary shares with zero stales. The signed v1.0.23 node verified the five timed proofs, warmup and alternate-height proof from each run. The release manifest records the component revisions and hashes.
