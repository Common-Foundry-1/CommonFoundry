# 5x RC difficulty candidate: qualification hold

Date: September 21, 2026. Runtime source examined:
`a0e359571e5f904d522be63378774ced8292b4e4`.

**Decision: do not approve the final mainnet setting yet.** The owner has chosen
5x RC starting difficulty and the RC minimum. This investigation is a statistical
pre-screen, not complete block production, a hardware throughput benchmark, or
cryptographic/release approval. Neither runtime parameters nor mainnet pins changed.

**Follow-up:** the owner-approved isolated GPU test subsequently passed two full
blocks, two-node restart checks, and CPU-only cold-log recovery. Local core code
now supports separate initial/easiest targets without changing any released
profile. See [live qualification results](mainnet-5x-live-qualification-20260921.md).
The findings below describe the earlier statistical pre-screen, not that live run.

## Reproducible pre-screen

`crates/cmfd-consensus/examples/difficulty_rehearsal.rs` calls the actual integer
`next_work_target`, including the 180-entry window and target limits. It feeds
honest upper-median timestamp history matching `ChainState`, including the
virtual genesis. Pool jobs retain their issuance timestamp until the tip changes
(`pool::rotate_if_tip_changed`); the model uses that timestamp rather than giving
the verifier an artificial solve-time header.

The harness seeds the virtual genesis with the proposed starting target and
passes a separate easiest target to the retarget function. That models the
proposed split; the production `ChainState::new` still seeds from `pow_limit`.
It is not a runtime implementation or a way to activate this configuration.

Each run covers 36 scenarios, 64 seeded trials per scenario, 1,620 modeled
intervals per trial. It compares starting/minimum RC multiples of 5/1, 5/5 and
1/1, per-GPU rates of 20/25/35 FW/s, and fixed serial overhead of 8/16 seconds.
The schedules are 5 -> 20 -> 5 and 20 -> 1 -> 5, each phase lasting 540 modeled
blocks. A separate run models restoring the previous actual GPU count ten
minutes after each drop, even if no block has arrived yet.

Search uses independent exponential waiting times and assumes GPU rates add.
The latency cases are modeling assumptions informed by earlier proof timing,
not newly measured end-to-end times. It does not model competing tips, stales,
share queues, heterogeneous GPUs within one trial, adversarial timestamps,
real proofs, pool payouts, or peer admission. It starts no GPUs or services.

Both JSON approval flags remain explicitly false. Reports use exclusive file
creation so reruns do not overwrite earlier evidence.

## Representative results, not live block measurements

The following are medians across 64 trials at 25 FW/s/GPU, 8-second fixed
overhead, starting/minimum multiples 5/1. Reported recovery is time until the
first complete rolling 60-interval window averages at most 90 seconds. This
descriptive measure is not a promise of permanent settling or an agreed SLA;
even an immediately recovered network takes about an hour to fill that window.

| Scenario | First 10 intervals | Recovery-window observation |
| --- | ---: | ---: |
| Start with 5 GPUs | 27.2 minutes | 75.0 minutes |
| Start with 20 GPUs | 10.1 minutes | 60.6 minutes |
| 20 -> 5, no assistance | 33.7 minutes | 284.7 minutes |
| 20 -> 1, no assistance | 154.4 minutes | 689.5 minutes |
| 20 -> 5, restore 20 after 10 minutes | 16.7 minutes | 65.7 minutes |
| 20 -> 1, restore 20 after 10 minutes | 18.5 minutes | 66.3 minutes |

Steady-state medians of the final 180-interval means are approximately 59-60
seconds in the representative unassisted 5/1 cases. That does not establish
acceptable transient behavior. After 20 -> 1, the first interval's observed
95th percentile is approximately 59 minutes without assistance. The early
five-GPU startup is slower than the earlier search-only arithmetic suggested:
the frozen job timestamp plus startup median history can harden subsequent
targets before the completed solve interval is reflected in history.

At 5/5 (raising the floor as well as the start), the representative one-GPU
phase's final mean remains roughly 210 seconds. None of its 64 trials reaches
the descriptive <=90-second rolling window. This confirms why simply changing
`pow_limit` to the 5x target is not the requested configuration.

Using an initial 1x target improves startup in this model but does not eliminate
the long post-drop recovery once the network has reached the same higher work
rate. Changing only the starting number is not a retarget-response repair.

## Validation and evidence

- Native Windows/MSVC: five harness tests and eight existing difficulty tests
  passed; the example passes strict Clippy.
- Linux/WSL: five harness tests and eight existing difficulty tests passed. The complete unassisted report was
  reproduced byte-for-byte across Windows and Linux using Rust 1.94.1.
- Final unassisted report SHA-256, both platforms:
  `8cab23a43cb2959294033d2aaa61974b32e45f9a0897f00cd25344fe73674959`.
- Final Windows ten-minute-backup report SHA-256:
  `ff7bf3a88b718e1ccaad271beeebb3448c2527e0b6efc2e94a95ab8cea2cf411`.
- Harness source SHA-256:
  `0fd4fb54a279317df45710f517e9b475264aa1a1803b67c933c9ea8aab35528f`.

Local evidence directory: `C:/Source/_ops/commonfoundry-difficulty-rehearsal-20260921`.
Use `final-prescreen-windows.json`, `final-prescreen-linux.json` and
`final-backup-10min-windows.json`; earlier non-final files are retained but
superseded. These statistical results are not intended as release attestations.

Reproduce from the repository root (use a new output path):

```text
cargo +1.94.1-x86_64-pc-windows-msvc test --locked --offline -j 2 -p cmfd-consensus --example difficulty_rehearsal
cargo +1.94.1-x86_64-pc-windows-msvc run --release --locked --offline -j 2 -p cmfd-consensus --example difficulty_rehearsal -- --trials 64 --output prescreen-new.json
cargo +1.94.1-x86_64-pc-windows-msvc run --release --locked --offline -j 2 -p cmfd-consensus --example difficulty_rehearsal -- --trials 64 --backup-after-seconds 600 --output backup-new.json
```

On Linux use toolchain `+1.94.1`. Floating-point waiting-time simulation is
non-consensus; byte identity was observed for these runs, not guaranteed for
all compilers/platforms. Actual retarget arithmetic remains integer-based.

## Work still required for final approval

1. Finish authenticated mainnet plan/pin/packaging integration for the now-tested
   initial/easiest target separation. Local consensus/profile/fingerprint and
   snapshot support exists; released profiles still keep their original settings.
2. Decide whether the startup and unassisted recovery behavior above is
   acceptable. If not, review and test a retarget/timestamp design change before
   activation; do not quietly shorten a window or add an unreviewed rescue rule.
3. Extend the successful two-block full-proof/local-node/cold-recovery smoke
   check to controlled multi-GPU hashrate steps and final packaged P2P operation.
   Record search, proof, queue/propagation and stale work separately. Neither a
   two-block smoke check nor this simulation satisfies that larger requirement.
4. Final acceptance must cover the chosen implementation and actual test
   evidence, not just the owner's approval of the 5x candidate number.

The initial pre-screen did not start GPU work. The later live run used the local
RTX 5090 after explicit permission to pause the old Devnet-16 pool and restore it
afterward. AI01's public pool was left untouched throughout.
