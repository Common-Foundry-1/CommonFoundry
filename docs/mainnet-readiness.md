# October 3 mainnet readiness

## Fixed schedule

- Source and matching packages: **2026-10-02 17:00:00 UTC**, noon CDT.
- Mainnet mining: **2026-10-03 17:00:00 UTC**, noon CDT.
- Local zone: `America/Chicago`; the dates are in daylight time, UTC-05:00.
- The preparation window is exactly 86,400 seconds.

## Source baseline

The readiness branch starts at `08e63ad3862b82f7d2fc3853711bc4c1b314db66`,
the signed RC5 miner.2 release source. It includes RC5
`ae00bcacde01aaf1e54dcc0297d388165d677af2` and the qualified Ada/Blackwell
miner changes. The dirty older `C:\Source\CommonFoundry` checkout is not
the source for these changes. No running RC services are changed.

## Fair-start construction

The proposed mainnet genesis is SHA-256 over this exact byte sequence:

```text
"CMFD/MAINNET/BEACON-GENESIS/V1\0"
|| canonical_mainnet_launch_plan_sha256[32]
|| pinned_quicknet_chain_hash[32]
|| pinned_round_big_endian_u64[8]
|| verified_compressed_G1_signature[48]
```

The launch plan must bind finalized economic parameters, proof identities,
reward destinations, the schedule, and the beacon policy before source release.
The exact quicknet round is **32,747,812**. Its scheduled time is precisely the
announced start; it is not the latest round, the preceding round, or a selectable
fallback. If the round is late or unavailable, nodes wait for that same round.
Do not change the round or use operator-generated entropy as a fallback.

`cmfd-launch` verifies the round with `drand-verify = 0.6.2`, using quicknet's
RFC9380 G1-signature scheme and checked public-key deserialization. It derives
randomness locally from the signature. Relay-provided public keys and randomness
are not accepted. Parsing is bounded to 4 KiB and rejects extra/duplicate fields.
Its authenticated output type cannot be deserialized or constructed by callers.

The threshold beacon adds an explicit assumption: enough drand participants
must remain honest and withhold future-round shares until their scheduled time.
It does not guarantee equal Internet latency or equal mining hardware. It prevents
useful advance work only when the authenticated genesis is required by every
node, pool, wallet, mining, replay, and block-validation entry point.

The cryptographic component and CLI are the first implementation increment.
**Runtime/mainnet integration is not complete.** Existing RCNet identities and
consensus remain unchanged. A successful CLI verification is not mainnet approval.

Primary references: [drand specification](https://docs.drand.love/docs/specification/),
[drand security model](https://docs.drand.love/docs/security-model/), and
[drand-verify](https://docs.rs/drand-verify/0.6.2/drand_verify/).
Quicknet key, period, genesis, and chain hash were compared across api.drand.sh
and api3.drand.sh on 2026-09-19. Historical round 123 is the offline positive vector.

## Outstanding evidence and implementation

| Requirement | Current state | Completion evidence |
|---|---|---|
| One canonical source baseline | Readiness branch created from miner.2 | Final frozen source commit and source publication target |
| Exact UTC release/mining schedule | Pinned in cmfd-launch | Schedule CLI and timestamp tests |
| Signed launch-time entropy | Verifier component implemented; integration pending | Signature mutation vectors plus node/miner replay and anti-precomputation tests |
| Mainnet network/consensus identity | Pending | Canonical plan and mainnet profile, distinct from RC |
| Reward receiving addresses and custody | Awaiting owner decision | Public destinations plus custody/recovery evidence |
| Independent reproduction and review | No accepted independent record located yet | Named reproducer, signed report, independent crypto/wallet review |
| Windows/Linux release packages | Pending mainnet configuration | Clean installs, signature/checksum verification, matching runtime identity |
| Seeds, discovery, explorer | RC evidence needs mainnet rehearsal | Independent node results and mainnet service configuration |
| Pool payout and reorg lifecycle | Evidence collection pending | Mature-reward payout and reorg/restart reconciliation logs |
| Storage capacity | Existing unpruned proof load needs a mainnet plan | Measured growth and provisioned capacity/retention decision |
| Recovery and update | Rehearsal pending | Backup/restore, interrupted append, restart, upgrade/rollback results |
| Final launch rehearsal | Pending | Exact intended packages, future-round start, delayed-beacon handling, fresh-wallet transfers |
| Source release 24 hours early | Not yet executed | Public source and matching package timestamps at agreed release time |

OTC completion is deferred until mainnet and is not part of launch activation.
Carry forward successful unchanged RC evidence; repeat affected checks and the
final end-to-end launch rehearsal. Do not mark this checklist complete merely
because the component tests pass.
