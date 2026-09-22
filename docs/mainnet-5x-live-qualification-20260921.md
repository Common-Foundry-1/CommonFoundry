# Isolated 5x starting-target proof and recovery qualification

Run date: September 21, 2026 local / September 22 UTC.

**Passed:** two real ProductionV4 blocks, CPU admission by two isolated Node
instances, altered-proof rejection, reopen checks, and CPU-only replay from
copies of their logs without startup caches. **Not approved:** final mainnet
difficulty, multi-GPU dropout recovery, final plan/pins/packages or mainnet launch.

## Actual configuration

- RTX 5090, UUID `GPU-0a1365a4-18dc-3472-b037-257b8ccc3a98`, Windows/WSL Ubuntu 22.04.
- Full authenticated ProductionV4 bank/fixed inputs and the existing RC5 GPU workers.
- Initial target: `000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb`.
- Easiest target: `003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
- Isolated Testnet-1 network ID with a distinct genesis/fingerprint; no P2P sockets.
- Genesis time: `1790038348`; genesis hash: `ecd2ffb4e7da85bdfc1867a65239cc3f62288d1bf4a7484d5fd6358809101dcf`.
- Consensus fingerprint: `61389f8632422e712d68b1370f375f65b5568e5281f86f313e6e60d6118a8c7b`.
- Source base `a0e359571e5f904d522be63378774ced8292b4e4` plus local initial-target
  and qualification-test changes. This was not a signed release build.

The optional initial target is validated as nonzero and no easier than the
limit, committed to the fingerprint, and used for the virtual genesis history.
Snapshot validation checks that same initial target. Existing profiles retain
`None`, preserving their original fingerprint and initial/minimum behavior.
Authenticated-mainnet profile mutation tests also reject changing this field.
Mainnet manifest, release-pin and package integration remain unfinished.

## Measured results

| Measurement | Block 1 | Block 2 |
| --- | ---: | ---: |
| Actual search attempts | 17,050 | 1,148 |
| Search time | 1,462.394 s | 98.837 s |
| Prover-reported online phase | 43.931 s (first use) | 6.479 s (warm) |
| Full winning replay/proof pipeline | 56.409 s | 18.557 s |
| Build-time CPU proof verification | 0.292 s | 0.311 s |
| Node A admission | 0.380 s | 0.403 s |
| Node B admission | 0.384 s | 0.365 s |
| Reopen both nodes, including model authentication | 59.225 s | 59.495 s |
| Complete proof size | 12,025,320 bytes | 12,025,320 bytes |

Block IDs:

- 1: `095f1d67f2b58fd6421b787da37527164f1213e3350234e4c07be28c334e8a2f`
- 2: `601d5fc7be11ebaa7a87b8be13e8af8ac9147dc1ab25a33f4a776e8182e84311`

The first next-target was `0026666666666666666666666666666666666666666666666666666666666661`,
easier than the starting target but still harder than the RC minimum. The next
target and chain tip survived both restarts. The producer's CPU self-checks
rejected final/matrix/opening/truncation/byte mutations; Node B additionally
rejected a modified serialized proof before admitting each original block.

The follow-up copied only each disposable test node's `blocks.log`,
`network.meta` and test `wallet.key` into new directories, omitting all startup
caches. Both CPU-only cold replays recovered height 2, the exact tip, expected
next target, and unchanged wallet files. Including model authentication, these
took 31.594 and 31.519 seconds. No GPU was used for this recovery test.

Sampled peak whole-GPU memory was 26,166 MiB, including desktop/other allocations;
peak sampled temperature was 59 C. These are observations, not isolated prover
VRAM requirements or guaranteed maxima. No clock, power-limit or driver changes
were made.

## Scope and interpretation

This uses the real production-sized proof and normal Node admission/persistence,
not a tiny relation or mocked proof. Node B decoded the serialized block and
verified it using its separately authenticated verifier. Both Node instances
were in one test process; this is not a separate-host/P2P or independent-code audit.

The test uses the pool's bounded batch search on one GPU with local WSL scratch,
not a five- or twenty-GPU final-miner benchmark. The first search was a long
random trial; neither search duration establishes an average block interval.
Genesis was set before model/worker preparation, so the first retarget also
includes preparation time. This is not an exact future-beacon launch rehearsal.
The first proof's cold upload/initialization cost must not be hidden by quoting
only the warmed-up 6.479-second online phase. Search and the complete pipeline
must also remain separate from that phase measurement.

The prior statistical investigation still shows slow unassisted recovery after
hashrate drops. Two valid blocks do not close that gate. Actual mainnet pins are
still unset, no public binaries or live network parameters were changed, and
the evidence reports deliberately keep `final_setting_approved` false.

## Evidence and regression checks

Local evidence: `C:/Source/_ops/commonfoundry-difficulty-rehearsal-20260921/live-gpu-002`.

- `REPORT.json` SHA-256: `635fbb55831675ccb3bccdb2dd3f6e7501af8ea722a6a8b114788dba4c797945`.
- `COLD-RECOVERY.json` SHA-256: `9360cfc07e420b11129a694fdee7406c2501d98761d80d90f4d9bf43c76b1170`.
- Block 1 frame SHA-256: `4e986be1db15a2692c9781551595d806f03dbdc887e53a44135f5d5283c767ca`.
- Block 2 frame SHA-256: `9621dc1b520a31b78b4d91f3f97d2894c70fe32f9ddc350f126a18dd2e529bc1`.
- 193 base consensus tests passed on Windows and Linux.
- Seven authenticated-mainnet boundary tests passed on Windows, including initial-target rebinding rejection.
- Four RC profile tests and two RC metadata tests passed. The metadata test feature
  guard was corrected so an RC build is not compared to a Devnet metadata fixture.
- The GPU proof test and the CPU-only cold-recovery test each passed separately.

The failed earlier run `live-gpu-001` is retained. It authenticated both nodes'
models but failed a test-harness metadata comparison before starting GPU proof
work; that comparison was corrected. It is not counted as a successful proof run.

The user approved pausing only the old Windows Devnet-16 pool. It was restored
through its original scheduled task; after its roughly 19-minute full-chain
startup replay, all original listeners, its health endpoint and original GPU
workers were verified. Its chain-log length, network metadata and TLS certificate
were retained. Its detailed dashboard API still timed out, as it did before the
pause; that endpoint's responsiveness is not claimed as repaired.
AI01's public pool and dashboard remained active and unchanged, with no restart.
