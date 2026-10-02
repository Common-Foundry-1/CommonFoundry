# Pool-owned idle GPU search (experimental, not released)

This branch prototypes opt-in native Linux search on the pool's own prover GPU.
It is not in v1.0.0, is not approved for launch deployment, and must not be
installed over the pinned mainnet node or scheduled launch controller.

## Design

The pool already owns a persistent replay worker and a persistent proof worker.
Idle search reuses that same replay worker instead of starting another miner
with a duplicate model allocation. `RUNBATCH` temporary CUDA allocations are
freed by the existing worker before it acknowledges completion. After a
winning nonce has been replayed in full and its final activation checked, the
pool sends the existing `EVICT` command and waits for acknowledgment before
proving. This frees the replay model during proof generation. The same worker
reloads the pinned model when search or share replay resumes.

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

## Opt-in interface

The node's existing `pool-serve` command gains
`--production-v4-pool-idle-search` alongside `--allow-address-only-payouts`.
It defaults off and rejects Windows/WSL use. This is a developer interface, not
an instruction to run it on mainnet yet. No launcher/systemd auto-enable is
provided by the node itself. The updated service launcher also accepts the
optional JSON boolean `idle_gpu_search`, defaulting to `false`. Set it to
`true` only with the matching new node binary. Preflight refuses a binary
whose `pool-serve --help` lacks the new option. Do not start an additional
search miner on this GPU.

Logs distinguish pause, resume, share result and stopped states. A search or
verification worker error disables further idle search; connection failures
stop the optional client. There is no blind automatic worker restart or retry
of an uncertain share submission. The proof service is not restarted. On
normal shutdown the local client is stopped before proof verification.

Worker pipe writes and reads have elapsed-time deadlines and bounded queues,
line counts and byte counts. A search request has a 30-second deadline and
checks shutdown cancellation every 25 milliseconds. Other requests have a
five-minute deadline; worker startup has a three-minute deadline. A timeout
terminates the owned worker process group on Linux and waits up to three
seconds to confirm the parent exited. A later verification may restart only
the exact recorded worker command after that exit has been confirmed. Idle
search remains disabled after a worker fault; the operator must investigate
before restarting the pool. Neither PID scans nor broad miner-kill commands
are used by this feature.

## Release gates still required

- Compile and test the native Linux CLI and real client/server integration.
- Repeated full proof cycles on the intended RTX 5070 Ti, including VRAM
  measurement and comparisons against a dedicated-prover baseline.
- Candidates from remote rigs during a local batch; multiple queued candidates;
  stale jobs and reorgs; invalid submissions; ordinary payout accounting.
- Native Windows and Linux timeout, output-limit, cancellation and worker
  replacement tests now pass. GPU-driver failure cases still need the hardware
  qualification below; a confirmed CPU child exit alone is not a performance
  or memory-capacity measurement.
- Crash/EOF/error paths, memory release, clean shutdown, connection recovery
  policy, and performance/fairness under sustained load.
- Reviewed packaging, signed build, operator documentation and independent
  release verification. Existing launch artifacts stay unchanged.

Offline scheduling tests do not establish actual GPU memory use, proof
success, mainnet acceptance, payouts, or production readiness.
