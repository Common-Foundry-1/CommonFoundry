# Mainnet fork runtime at 67,535

Install each release in a new directory and keep a complete stopped backup of
the previous runtime, data, wallet key, work-status files and prune anchors.
The fork-aware node/wallet upgrades the exact legacy metadata without replacing
the wallet key. Restoring an old binary requires the untouched complete backup;
old software cannot follow compact blocks after activation. Recovery after H
uses an upgraded binary and an archival peer that can serve the missing blocks.

`FORK-RUNTIME.json` records the activation identity and hashes every program the
height router can execute or import. Its compact CUDA worker can be a retained
qualified build; inspect its component source commit and SHA-256. All files are
also covered by `MAINNET-PACKAGE.json` and the signed archive checksums.

Mainnet wallet Solo uses `production-v4/cmfd-mainnet-fork-prover`. The router
selects legacy v1 below 67,535 and compact v2 from 67,535, including a reorg.
Serial mode releases replay before proving and the proof process before replay
reloads, so their CUDA allocator caches do not overlap on the same card.

For Linux pool-service operators, keep all payout, TLS, worker and GPU settings
while updating the reviewed executable hashes. Add
`expected_fork_manifest_sha256` with the SHA-256 of this release's
`FORK-RUNTIME.json`. `expected_proof_worker_sha256` continues to pin the legacy
`real_bank0_relations`; the additional manifest pins the router and compact
worker. Existing ledgers need an offline copy-only rebind to the new fingerprint
before the updated pool starts. Compare generations, balances and pending payouts.

If replay and proving share one physical card, set `serial_gpu: true` and use
one matching replay/proof GPU UUID. Keep `proof_resident_banks` false. Separate
non-overlapping GPUs can retain the existing parallel setup. These templates
are staged files; extracting an archive does not install or start a service.

Production promotion still requires operator integration results, the complete
qualification report and review of the compact proof. Windows EXEs additionally
require trusted timestamped Authenticode before archives/checksums are generated;
the SSH release-checksum signature is a separate archive authentication step.
