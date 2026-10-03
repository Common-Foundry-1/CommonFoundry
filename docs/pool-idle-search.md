# Pool-owned idle GPU search (experimental, not released)

This update adds opt-in native Linux search on the pool's own prover GPU.
It is not in the original v1.0.0 package. Use the separately signed update in a
controlled maintenance window after launch; keep the original scheduled launch
controller and its pinned node intact through activation.

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
It defaults off and rejects Windows/WSL use. The node does not install or enable
systemd units. The updated service launcher also accepts the
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
before restarting the pool. The prover's CUDA allocator retains allocations
after a completed job, so in idle-search mode the pool retires that owned
prover process after each successful full proof and restarts its exact pinned
command for the next candidate. This frees its context before search reloads
the replay model. Neither PID scans nor broad miner-kill commands
are used by this feature.

## Qualification

On the physical RTX 5070 Ti (16 GB), three consecutive synthetic-template full
proof cycles completed with the real input set and CPU verification. Each
12,025,320-byte proof was followed by resumed idle search. End-to-end cycle
times, including reload/restart and resume, were approximately 53.0, 68.7 and
71.4 seconds on that host. These are qualification observations, not a sustained
pool throughput guarantee or live mainnet block acceptance. The first candidate
found a retained-prover-memory failure; retiring the completed prover context
fixed it. That failure was preserved in the private operations evidence.

Native Linux scheduler, real TLS/share accounting, worker timeout/cancellation,
output-limit and exact-command restart tests passed. Existing pool protocol,
accounting and payout-protection tests passed as well. Service configuration
tests cover the opt-in boolean and legacy configuration behavior. Root launch
plan and verified-beacon requirements are unchanged.

## Operator validation after launch

- Verify accepted shares and independently propagated full blocks on the actual
  network; retain your normal mature-payout and reorg reconciliation checks.
- Measure remote-miner latency and available VRAM on your own host. Incoming
  work takes priority; search may remain idle under sustained verification load.
- Treat startup/reload time as part of prover capacity planning. Qualification
  on one GPU and host does not establish performance on every architecture.

Synthetic hardware proof tests do not establish live mainnet transactions,
maturity, payouts or chain admission. Those checks require the activated network.
