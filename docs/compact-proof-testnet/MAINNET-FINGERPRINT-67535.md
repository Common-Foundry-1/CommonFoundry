# Mainnet compact-proof fingerprint at height 67,535

The compact-proof mainnet fork identity is pinned to:

```text
9009948f6eab38b5b3dcee13eda9f6ef03e0db863c435cb97c1d4c3e124eb360
```

The mainnet compact proof-system digest is:

```text
d1671fc4760134bf86f0b37d8694f4827037e5cea2642e312cb2eb705f3aef0d
```

Both are defined in `crates/cmfd-consensus/src/compact_mainnet_fork.rs` and
reproduced in `MAINNET-FORK-IDENTITY-67535.json` with the exact hash preimage.
They commit to the existing mainnet identity and the following schedule:

| Height | Proof | Ordinary-node admission |
| --- | --- | --- |
| 0â€“67,534 | Existing version 1, 13 MiB frame allowance | Complete proof checks and current mandatory work replay |
| 67,535 onward | `CMFDDR02` version 2, packet strictly below 6,000,000 bytes and frame at most 6,100,000 bytes | Complete repaired proof verification, block/transaction/target checks; no mandatory mining-work replay |

The new proof-system digest binds the canonical packet version, compression,
six-commitment opening, BaseFold 1/270/16 parameters and evaluation absorption
before the batching challenge. It uses a mainnet-specific domain; the testnet
digest and network ID are not used as the mainnet fork identity. Optional
independent replay auditing does not become an ordinary-node admission rule.

The fork fingerprint also binds the activation height, predecessor
fingerprint, model/fixed-artifact digests, workload algorithm version, the
16 MiB block limit, both proof-system digests, proof limits, and the replay
policy before and after activation. The predecessor fingerprint commits the
existing genesis, monetary policy and transaction rules. Mainnet's network ID
and existing keys remain on the same chain.

Reproduce the manifest from this exact source:

```text
cargo run -p cmfd-consensus --example compact_mainnet_identity --locked
```

`fingerprint()` uses BLAKE3 derive-key mode with context
`CMFD/MAINNET/COMPACT-FORK/FINGERPRINT/V1`. Its preimage is the fixed-order,
260-byte encoding published in the JSON: integers are little endian, hashes
are raw bytes, booleans are one byte. Known-answer tests pin both new digests.
Changing H, proof identity, limits, model, or admission policy changes the
fingerprint. `from_mainnet_params()` refuses parameters whose existing
fingerprint differs from the pinned mainnet predecessor.

Every `production-mainnet` build of this fork source reports this fingerprint
in `network-info` and enforces the scheduled proof rules. Peer wire identity
remains the predecessor below H, with a rehandshake at the boundary. Storage
upgrades and operator testing are described in `MAINNET-IMPLEMENTATION-PLAN.md`.
The earlier H=65,535 fingerprint is superseded; old signed assets are unchanged.
