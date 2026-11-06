# Compact proof testnet operator kit: local pilot

This kit records the Linux pilot build and its network identity for pool operators preparing a canary. The first pool is running on loopback with two independent peers and three accepted compact-proof blocks. Public seed and pool addresses will be supplied with the public canary package.

## Network and artifact pins

| Item | Identity |
| --- | --- |
| Network ID | `dcda3e81881e148a45970d2e7157b77f27e931e696df28468390ce79bb1e14cb` |
| Virtual genesis | `e4d360dfffd368c83992c786a4842ed211aa2043cc6a1bc5ad487919a6f93754` |
| Proof | Version 2, `CMFDDR02`, maximum direct packet 6,000,000 bytes |
| Linux node SHA-256 | `5d6f8b7fda74a6a59756971ca5ef0ead7e567766fe958b42e26dcf857812672b` |
| Linux miner SHA-256 | `0adefbe51ef00b1753497a7a39a09e6aa6ac8db635df445a4599e2711a53c18a` |
| Direct GPU proof worker SHA-256 | `aca6a7cbb590db67e9acb23c8a92189ea5d652d617cb8db0f78ee0a246a11389` |
| ProductionV4 replay worker SHA-256 | `33ce76f3832e7703d5aa8200ed51acfe3becfcfb2c2b063886aaf1db5ab1f9f0` |
| Model bank SHA-256 | `5f9b213c3bda51b74e4ebabb26607b67385d613aa8d99af915a48ab063e17d4e` |
| Fixed artifact record SHA-256 | `ea218831aa567e486426ded77c84a5752a817329c496e3557c6d43577f0afe79` |

The node authenticates the complete 6,442,975,416-byte model bank and fixed record at startup. Place the fixed codeword and tree files beside that record. The pool can assign share replay and full proving to separate GPUs, which is a useful layout for 16 GB cards.

## Local pool shape

Use a dedicated testnet data directory, a testnet payout address, and a TLS certificate whose SHA-256 is supplied in the miner URL. The pilot uses RPC `23443`, P2P `23444`, and pool `23445`; a second node may choose alternate local bind ports while retaining the same network ID. The node and pool report their network identity in `network-info` and `/v1/status`.

The pool's ProductionV4 worker options are `--production-v4-pool-replay-worker`, `--production-v4-pool-proof-worker`, and `--production-v4-pool-scratch`. `--production-v4-pool-replay-gpu` and `--production-v4-pool-proof-gpu` choose separate devices. The miner's `pool` command uses a `cmfd+tls://NUMERIC_IP:PORT?pin=SHA256` URL and the matching testnet payout address.

The first loopback pilot intentionally uses a zero-bit share target to exercise the full block path with one deterministic share. The public canary will use a calibrated mining target and published connection details so pools can measure normal block cadence, propagation, and stale rates.
