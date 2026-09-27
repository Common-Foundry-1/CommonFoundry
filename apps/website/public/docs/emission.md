# CommonFoundry emission schedule

CommonFoundry uses a five-year linear initial-emission phase followed by a
permanent miner-only tail. There are no halvings.

Consensus assumes a 60-second target and defines one emission year as exactly
365 days. The declining phase therefore contains:

```text
N = 5 * 365 * 24 * 60 = 2,628,000 real blocks
```

This is height-based: it lasts five years only when realized block production
matches the 60-second target on average.

For real block height `h` from 1 through `N`, with initial subsidy
`R0 = 500 CMFD`, the subsidy in atomic units is:

```text
declining_subsidy(h) = floor(R0 * (N - (h - 1)) / N)
```

Integer arithmetic is exact and uses a widened intermediate before division.
Block 1 receives exactly 500 CMFD. Block 2,628,000 receives 0.00019025
CMFD. The continuous declining component reaches zero at the next boundary,
so block 2,628,001 begins the permanent 5 CMFD tail.

The tail deliberately replaces the declining phase rather than extending its
line. The total reward therefore moves from 0.00019025 CMFD on the last
declining block to 5 CMFD on the first tail block. This is an explicit
consensus rule, not a rounding accident.

The exact scheduled supply from real blocks 1 through 2,628,000 is
657,000,249.98688 CMFD. Tail issuance is perpetual and is not included in that
number, so total supply remains unbounded after five years.

Before the tail, every block divides its subsidy as follows:

- 70% miner;
- 25% immediately spendable steward award; and
- 5% immediately spendable community fund.

At and after block 2,628,001, the full 5 CMFD subsidy goes to the miner. All
transaction and channel-close fees remain burned in both phases.
