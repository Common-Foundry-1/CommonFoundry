# Mainnet starting-difficulty decision

This is a planning note, not an approved parameter or a changed network setting.
The mainnet pin remains unset. Calculations use the existing target comparison
and the historical RC5 miner.2 console measurements, not current network telemetry.

On September 21 the owner selected **5x RC starting difficulty with the RC
minimum**, expects approximately 5-20 participating GPUs, and can supply reserve
GPU capacity. This selects the candidate, not final qualification. The subsequent
[statistical pre-screen](mainnet-difficulty-rehearsal-20260921.md) found slow
unassisted recovery and startup overshoot. Full-block sign-off is **not approved**;
the parameter split and actual packaged proof/recovery run remain outstanding.

## What the current code does

Released RC builds use `pow_limit` for both the starting target and the
largest/easiest target the retarget algorithm can ever produce. A harder limit
cannot later be relaxed beyond itself when fewer miners join or hash rate leaves.
The September 21 local qualification work adds a separately validated,
fingerprint-bound `initial_target` to consensus parameters and node profiles;
existing released profiles retain `None`, preserving their prior behavior.
The two-node full-proof/restart test exercised the actual 5x start / 1x minimum.
Mainnet plan/pin/packaging integration and final qualification are still pending.

The target is recalculated using up to 180 effective median timestamps and
targets. The history includes the virtual genesis. It does not wait for 180
mined blocks: after the first accepted block there are two history entries and
the next target can change. The measured span is clamped to between one third
and three times its expected span; the final result is capped by `pow_limit`.
This bounds the multiplier against the window's average target, not necessarily
against only the immediately previous target.

## RC baseline and search-only estimates

RCNet-1 uses target
`003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, giving a
valid-digest probability of exactly 1/1024 under the uniform-digest assumption.
For a 256-bit inclusive target T, expected attempts are `2^256 / (T + 1)`.
At a constant aggregate rate H, mean search time is expected attempts divided
by H. A single GPU's nominal 60-second search threshold at the RC floor is
about 17.067 FW/s.

| Measured GPU/configuration | Historical console FW/s | Mean search at RC floor, one GPU | Ten identical GPUs, search only |
| --- | ---: | ---: | ---: |
| RTX 4070 Ti SUPER | 20.285 | 50.48 s | 5.05 s |
| RTX 5070 Ti | 27.59 | 37.11 s | 3.71 s |
| RTX 5090 | 34.84 | 29.39 s | 2.94 s |

These are arithmetic scenarios, **not block-time forecasts**. They exclude
proof-production latency, pool replay/queue limits, propagation, stale work,
retarget feedback and heterogeneous hardware. The ten-GPU column assumes rates
add linearly; it does not qualify a multi-GPU rig's scaling. Console samples are bounded
historical measurements; the 5090 shared its GPU with pool/proof work. Do not
substitute the higher isolated GPU-kernel rates for end-to-end network capacity.
See [miner.2 release measurements](release-notes/v0.1.0-rc.5-miner.2.md) and the
linked device qualification records. Physical 20/30-series performance and
8 GB qualification are still not established by those measurements.

## Recommendation before freezing the plan

Keep the RC limit as a rehearsal baseline, not a silent mainnet default. Choose
the final floor for the smallest network we actually intend to support, then
measure complete block production and recovery after a hash-rate drop. Check
the larger-network startup burst separately. A floor chosen from an optimistic
fleet estimate cannot rely on the retarget to rescue an underpopulated launch.

Separating the starting target from the minimum difficulty is a deliberate
protocol/manifest change requiring review and rehearsal; it is not an existing
released configuration switch. The locally tested consensus/profile support
must still be integrated with the authenticated mainnet plan and release pins.
The final target, reward destinations
and full economic/rule configuration must be reviewed and signed together in
the canonical mainnet launch plan.
