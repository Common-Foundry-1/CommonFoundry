# Explorer resource qualification - September 25, 2026

These are internal, repeatable resource checks, not a mainnet approval or a
whole-node hardware requirement. They do not activate mainnet or change proof
verification, fork choice, stored records, monetary rules or launch timing.

## Lookup metadata at a bounded 30-day shape

The ignored `explorer_dense_index_shape` test populates the actual block,
transaction, address-history and active-output-reference containers. Its IDs
are synthetic and its durable locators are deliberately invalid; there is no
log, accepted chain or proof validation in this measurement.

The measured shape contains:

- 43,200 canonical blocks (30 days at one block per minute), 20 transactions
  per canonical block, one retained sibling every ten blocks and an additional
  10,000 same-height siblings for an intentionally heavy fork-tail case.
- 57,520 retained block entries, 1,136,080 distinct transaction IDs and
  1,150,400 transaction occurrences, including cross-fork duplicate IDs.
- 2,473,360 address-history entries and 993,600 active output references.
- Separate processes for 4,100 history addresses and for 1,150,404 history
  addresses. These are workload shapes, not predictions of adoption or traffic.

New transaction IDs now reserve one location instead of the four slots
allocated by a default vector's first push on the exercised targets. Lists
still grow for all retained fork occurrences; no history is dropped. For this
shape, transaction-location capacity fell from **182,428,000 bytes** to
**46,616,800 bytes**, excluding hash-table buckets and allocator overhead.

Windows debug test-process observations (100 ms nominal sampling):

| Address distribution | Previous peak working set | Updated peak working set |
| --- | ---: | ---: |
| Concentrated | 664.52 MiB | 525.78 MiB |
| Unique recipients | 1,479.89 MiB | 1,340.59 MiB |

These process figures include fixture construction and container overhead,
but exclude the authoritative consensus UTXO set, proof bodies, disk history,
verifier/model startup, HTTP service and other node state. They are not a
promise of production node memory usage. Repeat measurements can vary.

The heavy fork-tail case still filters retained side-branch entries: 20 hot
address-page lookups took 1.26-1.53 seconds total in the updated debug samples;
100 transaction lookups across the fork tail took 0.27-0.33 seconds. This
change reduces allocation, not the asymptotic query cost. These are method
timings, not HTTP throughput, and the larger concentrated timing was not a
speed improvement over its baseline.

Reproduce the bounded shape in an isolated process (Rust 1.94.1 was used):

```sh
CMFD_INDEX_PROBE_MODE=concentrated cargo test --locked -p cmfd-node --lib \
  explorer_dense_index_shape -- --ignored --nocapture --test-threads=1
CMFD_INDEX_PROBE_MODE=unique cargo test --locked -p cmfd-node --lib \
  explorer_dense_index_shape -- --ignored --nocapture --test-threads=1
```

The optional `CMFD_INDEX_PROBE_BLOCKS` (20-43,200),
`CMFD_INDEX_PROBE_TX_PER_BLOCK` (1-20) and `CMFD_INDEX_PROBE_ORPHAN_TAIL`
(0-10,000) variables bound the shape. Defaults are the measured values above.
Do not run this manual qualification simultaneously with a constrained live
node; the unique-recipient shape can allocate more than 1 GiB.

## Valid transaction history and recovery

The separate ignored `explorer_dense_valid_history_recovery` test builds a
consensus-valid, disposable tiny-profile chain with 514 blocks and 10,241
signed transactions. Each appended block is normally validated and stored
with its exact reversible state delta. Only per-block fixture file flushing
is batched; the final log is synchronized before reopening.

Three paths must agree on the exact encoded chain state, transaction lookup
results, address views and active-output cache rebuilt from consensus UTXOs:

1. Full replay with a stale startup cache.
2. Restart using the freshly written startup cache.
3. Full replay after damaging the disposable optional cache's integrity digest.

The Windows debug run passed all three for a 6,117,006-byte log. Observed
opening times were 16.43 seconds, 0.289 seconds and 17.42 seconds respectively;
fixture construction took 52.97 seconds. The machine also performed other
CPU-only checks during parts of this run. These are functional recovery
measurements, not a production performance comparison or startup SLO.

The same valid-history fixture also passed under Linux in WSL: 13.10 seconds
for full replay, 0.178 seconds for snapshot restart and 13.13 seconds for the
damaged-cache fallback, with a 40.85-second build. WSL used the same physical
host; this is cross-platform functional evidence, not independent hardware or
a controlled Windows-versus-Linux speed comparison.

```sh
cargo test --locked -p cmfd-node --lib explorer_dense_valid_history_recovery \
  -- --ignored --nocapture --test-threads=1
```

`CMFD_RECOVERY_BLOCKS` defaults to 512 additional blocks (bounded 1-1,024),
and `CMFD_RECOVERY_TX_PER_BLOCK` defaults to 20 (bounded 1-20). The two funding
blocks and splitting transaction are additional. The test refuses an existing
fixture directory and removes only its own disposable directory on success.

## What remains outside this evidence

The tiny fixture's complete log is smaller than one production proof. It
does not establish startup time for a long chain of 12,025,320-byte V4 proofs.
Separate preserved-proof checks have exercised normal full CPU admission on
Windows and Linux; they are also not a dense production chain.

Startup snapshots still require an exact linear active-chain log, still scan
the full retained record chain, and fall back to full replay when retained
side branches make the current snapshot format ineligible. Long full-size
history, retained-fork growth, sustained query load, service-identity restore,
final signed-package smoke and operational recovery remain separate gates.
