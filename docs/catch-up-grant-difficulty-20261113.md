# Wallet catch-up after a mainnet difficulty drop

## Incident and cause

A v1.0.20 Ubuntu wallet resumed at height 47,869 after about a week offline,
roughly 11,400 blocks behind. The user's session logs repeatedly showed
`granted=0`, with `checked_easing` as the only nonzero refusal counter. After
installing the official trusted bootstrap at height 58,424, the same wallet
reported `granted=1` in its first catch-up session. That rules out a general
failure of relay grants on this wallet; it does not establish the behavior of
every block in the gap.

The published v1.0.20 work checkpoint is at height 20,912. Public explorer
block records returned these targets on 2026-11-13:

| Height | Target | `floor(2^256 / (target + 1))` |
| ---: | --- | ---: |
| 20,912 | `0000192a0b48bfa3a064801742910e48b5745321160cd7bd54eec53841fc26fc` | 666,708 |
| 47,869 | `00005e165a5bfbb5c68ffb77317a613c9541966b5ac40c093855ec7b54bf3ea1` | 178,315 |
| 52,000 | `00007405cadfd6a23e7d3dc12d507734f9454d6b72beaca1e486f6ef8027ee79` | 144,602 |

The work at 47,869 is 26.7% of the checkpoint block's work. The old reference
was `max(validated_work, checkpoint_work)`, and the easing guard required each
grant candidate to have at least half of that reference. It therefore refused
blocks near 47,869 even after a local work check had validated the chain's
lower difficulty. The fixed checkpoint floor can turn a legitimate sustained
difficulty decrease into a long period of forced local replay.

## Change and trust boundary

Use the work of the last validated block as the reference once both that block
and the release checkpoint are indexed. The reference remains held while any
granted block lies above the validated frontier, so grants cannot ratchet it
down. A block that is more than two times easier than that reference still
falls back to a local work check.

Cross-provider corroboration, the 60-block depth, release freshness, normal
block and transaction validation, durable grant records, and background work
checks remain in force. This change does allow grants during a difficulty drop
that the old checkpoint floor rejected. It needs independent review of that
trust-policy change before a signed wallet release.

## Verification

- `cargo fmt --all --check` and `git diff --check` passed.
- `cargo test -p cmfd-node --lib work_gate::catch_up_tests` passed: 40 tests.
- With `production-mainnet`, the focused `catch_up_tests` suite passed: 56
  tests. Fifteen loopback P2P tests initially failed because the sandbox
  denied local sockets; they passed when rerun with loopback access.
- The new regression uses the public targets above and checks both the
  legitimate decline through height 52,000 and refusal of a further threefold
  easier candidate.

The production-feature test used the v1.0.20 base commit as
`CMFD_BUILD_SOURCE_COMMIT` solely to satisfy the test build gate. These are
source tests, not a signed build or a live mainnet catch-up qualification.
Before release, run an isolated wallet catch-up from a low-difficulty height
against independent live relay groups, and qualify the exact packaged wallet
on Linux and Windows.
