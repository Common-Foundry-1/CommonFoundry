# Difficulty recovery comparison: ASERT candidate, not activated

The matrix proof-of-work relation is unchanged. This experiment changes only
the offline model of how the next work target is calculated. Production and RC
nodes still call the existing DGW-style adjustment; no network selects ASERT.

## Arithmetic verification

The offline candidate uses integer-only fixed-point arithmetic, the published
cubic coefficients, and a 512-bit intermediate to support CMFD's wider targets.
Signed division is truncated toward zero before signed shift decomposition,
matching the [Bitcoin Cash Node implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/pow.cpp).
No floating-point value enters target calculation.

`asert_reference_check` matched **14,000 cases across all 12 official vector sets**
from [BCHN's test-vector archive](https://download.bitcoincashnode.org/misc/data/asert/test_vectors/).
Additional unit tests cover full-width targets, zero/invalid inputs, extreme
signed times, exact half-life factors and monotonicity across signed boundaries.
These checks validate the arithmetic, not a complete timestamp/activation policy.

The reference files are saved locally at
`C:/Source/_ops/commonfoundry-mainnet-tests-20260922/asert-vectors`.
Run the `asert_reference_check` example with `--vectors` pointing to that directory.
It reads bounded numeric files and neither signs nor activates anything.

## Statistical results

All rows below use 128 seeded trials, a 5x initial target / RC minimum, 25 modeled
FW/s per GPU and 8 seconds of serial proof/verification/propagation overhead.
Each phase lasts 540 modeled blocks. Values are medians, not live measurements.
Recovery means the first complete rolling 60-interval window averaging no more
than 90 seconds; its approximately one-hour observation window must not be
confused with instantaneous adjustment latency.

| Offline policy | First 10 blocks, 5 GPUs | Recovery after 20 -> 5 | Recovery after 20 -> 1 |
| --- | ---: | ---: | ---: |
| Current DGW-180 | 26.23 min | 287.34 min | 694.31 min |
| ASERT, raw timestamp, 15-minute half-life | 8.85 min | 88.70 min | 129.02 min |
| ASERT, raw timestamp, 30-minute half-life | 8.64 min | 122.81 min | 199.76 min |
| ASERT, raw timestamp, 60-minute half-life | 8.52 min | 186.77 min | 350.27 min |
| ASERT, median timestamp, 30-minute half-life | 8.94 min | 126.03 min | 205.32 min |

The complete JSON reports include other GPU rates, overheads, initial/floor
combinations and percentile tails. They retain `final_setting_approved: false`.
They assume additive search rates and do not include competing branches, stale
work, hostile timestamps, real network traffic or proof generation.

## Before a production choice

- Test adversarial timestamps against CMFD's actual acceptance bounds. A faster
  response must not be evaluated only with honest clocks.
- Test long outages and sustained operation at the easiest target. Fixed-anchor
  algorithms can accumulate schedule lag at their limit; the original
  [ASERT analysis discusses this clipping behavior](https://toom.im/files/da-asert.pdf).
- Compare variance, bursts, first-block delay and pool proof capacity, not just
  the median recovery metric. A target computed from completed blocks cannot
  change while waiting for the first post-drop block.
- If selected, bind the exact algorithm, anchor, half-life and timestamp policy
  into the canonical plan/fingerprint and replay/snapshot validation; preserve
  existing networks' rules.
- Run controlled multi-GPU and final-package rehearsals before final sign-off.

This work is internal validation. No external cryptographic audit is claimed or
being requested from the owner.
