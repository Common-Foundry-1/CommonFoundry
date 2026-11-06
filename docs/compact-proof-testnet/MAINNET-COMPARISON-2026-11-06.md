# Released mainnet prover reference and compact testnet context

The unchanged **v1.0.20 mainnet prover** was measured on this RTX 5090 at
7001 MHz memory and 520 W. Public historical winners 43424 and 43425 were
replayed, proved and independently CPU-verified. Both the prover and replay
worker matched the release artifacts. The local runtime archive matched the
public v1.0.20 archive hash, and its embedded prover matched
`0202bbe9dc88a169fbee2e17c406a475503ca263080c8acea4d543dffc734135`.

With prepared workers and the replay model resident at the start of each
winning request, the measurements were:

| Measurement | Released mainnet, Linux disk | Released mainnet, RAM | Compact testnet, RAM |
| --- | ---: | ---: | ---: |
| Full replay and witness export | 1.018–1.549 s | 0.814–0.830 s | 0.923–0.945 s |
| Complete proof-worker request | 4.058–4.450 s | 4.123–4.231 s | 5.518–5.890 s |
| CPU proof check / compact node admission | 0.404–0.406 s | 0.415–0.454 s | 0.422 s |
| Winning request through that local check | **5.55–6.48 s** | **5.44–5.57 s** | **7.56–7.90 s** |
| Raw proof packet | 12,025,320 bytes | 12,025,320 bytes | 5,661,321–5,664,164 bytes |

The mainnet columns are an **offline winning-proof pipeline reference**, ending
at independent CPU proof verification. They exclude live mainnet node/pool
admission, transaction-state commit, PPLNS accounting and WAN propagation.
The compact column is the actual local pool-to-accepted-block measurement from
the earlier two fresh testnet blocks. Its shared GPU uses serial model
handoffs and reloads; the warm mainnet reference keeps replay's model ready
before the measured request. These endpoints and residency states are not
identical, so the table gives context rather than a live-mainnet speed ratio.

The warm-state reference puts current mainnet proving/checking around
5.5–6.5 seconds on this rig. The compact pool's current complete result is
around 7.5–8 seconds. It takes more generation time to produce its smaller
packet; the smaller proof and proof-only node work validation are the main
demonstrated protocol benefits. The previously reported 58% improvement
compares the optimized compact pool with its own earlier 18.48-second path.

A first reference that included replay-model reloads measured 6.60–7.78 seconds
on Linux disk and 6.35–6.67 seconds with RAM. Windows-backed witness files took
16.42–19.45 seconds. This isolates a large storage/integration cost and shows
why those earlier roughly 18-second measurements should not be treated as a
universal mainnet baseline. Linux-disk measurements here used Ubuntu WSL's
native filesystem, not a production pool server's physical disk.

Ten fresh mainnet-format proofs passed the independent checker across the two
reference runs. Every case reported the released default
`fixed_data_preload=false pinned_banks=0`; no prover environment optimization
override or consensus change was used. One-time worker readiness and the
explicit warm-model preparation are recorded separately and excluded from the
warm request times. There are only two winners per storage/state condition.

The legacy reference used the 32 GB card as-is under a 24 GiB workload abort
guard; its warm-run sampled workload peak was 13.87 GiB. The compact candidate's
13 GiB guard was unchanged, with its earlier 12.57 GiB sampled workload peak.
These are workload deltas above the desktop GPU baseline, not physical
16 GB card qualifications.

Mainnet services, chain state and wallet data were not changed. Only the owner
miner was temporarily paused; it was restored automatically with unchanged
task identity, 7001 MHz memory and 520 W. Both private RAM mounts and all large
witness scratch files were removed. Proofs, hashes and local timing logs are
retained under `target/compact-public/mainnet-baseline-20261106`.

See [the exact measurement record](MAINNET-COMPARISON-2026-11-06.json) and
[the compact full-path qualification](RAM-WITNESS-RESULTS-2026-11-06.md).
