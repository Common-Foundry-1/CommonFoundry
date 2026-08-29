# ProductionV4 independent verifier

The independent verifier is a clean Python implementation of the public
ProductionV4 verification contract. It imports no Common Foundry consensus
code and does not invoke the production Rust verifier. This gives the project a
second implementation for detecting specification ambiguity and shared
implementation mistakes before mainnet.

## Current acceptance boundary

The current slice independently verifies:

- the exact 12,025,320-byte transparent-proof framing;
- every canonical KoalaBear field encoding in the proof;
- the pinned algorithm, proof-system, and model-manifest identities;
- the challenge, final-activation, work, and transcript-statement BLAKE3
  derive-key bindings;
- the unsigned 256-bit work-digest comparison against the block target; and
- strict rejection of altered public claims, malformed statements, trailing
  bytes, and noncanonical fields.

This is not yet a complete cryptographic proof verifier. The result always
reports `full_cryptographic_proof_verified: false` until the independent
implementation also checks the KoalaBear extension-field/Poseidon transcript,
relation equations, Merkle authentication paths, and BaseFold folding and
terminal low-degree conditions. Those four items are the remaining work order.

## Inputs

For a preserved miner attempt, derive and check the public bindings directly:

```powershell
python scripts/production-v4-independent-verifier.py `
  --template D:\path\to\template.json `
  --proof D:\path\to\transparent-proof.bin `
  --json
```

Add `--write-statement D:\path\to\statement.json` to save a portable strict
statement. A second run with `--statement` verifies that every candidate claim
matches the independent recomputation:

```powershell
python scripts/production-v4-independent-verifier.py `
  --statement D:\path\to\statement.json `
  --proof D:\path\to\transparent-proof.bin `
  --json
```

The sole non-standard Python dependency is the hash-pinned `blake3==1.0.8`
package already listed in `scripts/requirements-release-integrity.txt`.
