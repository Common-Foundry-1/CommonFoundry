# Mainnet compact-proof fingerprint at height 65,535

The compact-proof mainnet fork identity is pinned to:

```text
5b9626178bb3777230ceda1cfc0fee5a8872ad0bb0ac1c5d0c7457cf67f083a5
```

The mainnet compact proof-system digest is:

```text
d1671fc4760134bf86f0b37d8694f4827037e5cea2642e312cb2eb705f3aef0d
```

Both are defined in `crates/cmfd-consensus/src/compact_mainnet_fork.rs` and
reproduced in `MAINNET-FORK-IDENTITY-65535.json` with the exact hash preimage.
They commit to the existing mainnet identity and the following schedule:

| Height | Proof | Ordinary-node admission |
| --- | --- | --- |
| 0–65,534 | Existing version 1, 13 MiB frame allowance | Complete proof checks and current mandatory work replay |
| 65,535 onward | `CMFDDR02` version 2, packet strictly below 6,000,000 bytes and frame at most 6,100,000 bytes | Complete repaired proof verification, block/transaction/target checks; no mandatory mining-work replay |

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

This establishes the identity for the mainnet fork implementation to consume.
The current released node's active `network-info` still reports the old
fingerprint until the dual proof-rule, storage and peer transition is wired
into its mainnet activation path. Defining this identity alone does not ship
or activate the upgrade.
