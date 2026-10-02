# Pool-owned idle GPU search (experimental, not released)

This branch prototypes opt-in native Linux search on the pool's own prover GPU.
It is not in v1.0.0, is not approved for launch deployment, and must not be
installed over the pinned mainnet node or scheduled launch controller.

## Design

The pool already owns a persistent replay worker and a persistent proof worker.
Idle search reuses that same replay worker instead of starting another miner
with a duplicate model allocation. `RUNBATCH` temporary CUDA allocations are
freed by the existing worker before it acknowledges completion. The replay
model stays resident because verification also needs it.

A pool-local scheduling gate serializes optional search with share replay and
full proofs. Queued verification takes priority over a new search batch. An
in-flight batch completes before yielding; this is not instantaneous kernel
preemption. All connected miners use the same verification path, so remote
submissions take priority too. Search resumes only once verification has
released the gate. Continuous verification load can intentionally starve idle
search; pool service has priority.

The local client releases the gate before submitting its own share, preventing
a self-deadlock. It connects over the ordinary pinned TLS protocol as worker
`pool-idle-search`, uses the configured pool block-reward destination as its
payout address, and earns only through the same share accounting as other
miners. No payout percentage, proof rule, difficulty or network message changes.

## Proposed opt-in interface

The node's existing `pool-serve` command gains
`--production-v4-pool-idle-search` alongside `--allow-address-only-payouts`.
It defaults off and rejects Windows/WSL use. This is a developer interface, not
an instruction to run it on mainnet yet. No launcher/systemd auto-enable is
provided. Do not start an additional search miner on this GPU.

Logs distinguish pause, resume, share result and stopped states. A search or
verification worker error disables further idle search; connection failures
stop the optional client. There is no blind automatic worker restart or retry
of an uncertain share submission. The proof service is not restarted. On
normal shutdown the local client is stopped before proof verification.

## Release gates still required

- Compile and test the native Linux CLI and real client/server integration.
- Repeated full proof cycles on the intended RTX 5070 Ti, including VRAM
  measurement and comparisons against a dedicated-prover baseline.
- Candidates from remote rigs during a local batch; multiple queued candidates;
  stale jobs and reorgs; invalid submissions; ordinary payout accounting.
- Bound worker I/O and shutdown when a CUDA worker hangs. The inherited
  persistent-worker pipe read currently has no elapsed-time deadline; a hung
  search must not hold proof service indefinitely. This is a release blocker.
- Crash/EOF/error paths, memory release, clean shutdown, connection recovery
  policy, and performance/fairness under sustained load.
- Reviewed packaging, signed build, operator documentation and independent
  release verification. Existing launch artifacts stay unchanged.

Offline scheduling tests do not establish actual GPU memory use, proof
success, mainnet acceptance, payouts, or production readiness.
