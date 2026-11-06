# Compact proof testnet implementation plan

The first network is a fresh, isolated ProductionV4 direct-proof testnet built from the v1.0.20 release branch. It exercises the full ForgeMatrix workload and the same model, field, hash, and BaseFold 1/270/16 parameters. Blocks carry one self-contained direct packet and are accepted only after the node checks the complete block statement, all existing relation equations, the new shared-opening reduction, and all six BaseFold commitments.

## Pinned testnet identity

| Field | Testnet value |
| --- | --- |
| Network ID | `dcda3e81881e148a45970d2e7157b77f27e931e696df28468390ce79bb1e14cb` |
| Network ID derivation | SHA-256 of `CMFD/DIRECT-PROOF-TESTNET/V1/NETWORK-ID` |
| Virtual genesis parent | `e4d360dfffd368c83992c786a4842ed211aa2043cc6a1bc5ad487919a6f93754` |
| Genesis derivation | SHA-256 of `CMFD/DIRECT-PROOF-TESTNET/V1/VIRTUAL-GENESIS/2026-11-05` |
| Virtual genesis timestamp | 2026-11-05 00:00:00 UTC |
| Proof version | 2, restricted to this network ID |
| Direct packet codec | Version 2, `CMFDDR02`, canonical zlib level 1 |
| Initial local ports | RPC 23443, P2P 23444, pool 23445 |
| Data identity | `commonfoundry-direct-proof-testnet1` |
| Cold-start seed | Loopback for the first isolated two-node test |

The network ID and genesis are distinct from mainnet, RCNet-1, and ProductionV4 Testnet-1. The work challenge keeps the ProductionV4 computation, while the proof statement binds the new version and direct-proof system digest. The 16 MiB block limit and 1,024-transaction cap remain unchanged for this testnet.

## End-to-end gates

1. **Node acceptance:** pinned packet length and canonical decoding, final activation/work binding, all bank relations, three opening reductions, and one six-commitment BaseFold check. Old three-opening and altered packets are rejected.
2. **Fresh proving:** the GPU worker generates a proof for the new testnet network ID and block statement from fresh replay traces. No old proof is supplied as input. The node independently accepts the resulting block.
3. **Pool route:** ordinary shares keep the fast replay route; a winning share triggers full replay, direct proof generation, node verification, and block publication. Testnet payouts use dedicated addresses.
4. **Network behavior:** two nodes exchange blocks, catch up after a restart, reject wrong-network and malformed packets, and report compressed/uncompressed peer bytes.
5. **Wallet and operator kit:** a dedicated testnet data directory and address label, reproducible binaries and hashes, pool setup, explorer/sync checks, and a clean rollback to the original mainnet software.

The earlier 16 GB GPU research run produced complete 5.50–5.52 MB direct packets and accepted both on an independent CPU receiver. The version-2 canonical codec also accepted converted 5.67–5.69 MB packets on two fixtures. The [local pilot results](LOCAL-PILOT-RESULTS.md) now record two fresh testnet blocks, independent node admission, wallet credit, and restart catch-up. Optimized release-mode timing and the public pool canary are the next gates.
