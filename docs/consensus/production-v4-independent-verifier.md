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

When supplied the trusted fixed-artifact record, it additionally verifies:

- the record's pinned digest, canonical contents, production geometry, unique
  bank roots, and Poseidon commitment metadata;
- the independent `GF(0x7f000001)[X]/(X^4 - 3)` implementation and the pinned
  Poseidon2 width-16/rate-8 Fiat-Shamir transcript;
- all six matrix, shift, and cubic relation repetitions, including every
  partial-sumcheck round and terminal identity;
- the consensus-critical opening-claim routing and padding order;
- all three opening-reduction sumchecks and terminal identities; and
- the BaseFold batching, FRI-message, grinding-witness, and query-challenge
  transcript;
- every component and FRI Merkle authentication path, including commitment
  metadata; and
- every FRI query-fold equation and terminal low-degree condition.

Supplying the matching `MODEL-V2.bank` also authenticates its exact header,
payload root, all 384 per-layer roots, canonical byte range, length, and EOF,
then verifies both public initial-activation boundary evaluations.

With both trusted inputs supplied, a successful result reports
`full_cryptographic_proof_verified: true`. Without `--model-bank`, the public
initial-activation boundary checks remain pending and the full-verification
flag stays false.

## Inputs

For a preserved miner attempt, derive and check the public bindings directly:

```powershell
python scripts/production-v4-independent-verifier.py `
  --template D:\path\to\template.json `
  --proof D:\path\to\transparent-proof.bin `
  --fixed-artifact-record D:\path\to\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json `
  --model-bank D:\path\to\MODEL-V2.bank `
  --json
```

Add `--write-statement D:\path\to\statement.json` to save a portable strict
statement. A second run with `--statement` verifies that every candidate claim
matches the independent recomputation:

```powershell
python scripts/production-v4-independent-verifier.py `
  --statement D:\path\to\statement.json `
  --proof D:\path\to\transparent-proof.bin `
  --fixed-artifact-record D:\path\to\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json `
  --model-bank D:\path\to\MODEL-V2.bank `
  --json
```

Omitting `--fixed-artifact-record` performs only the public-binding and wire
checks. The artifact record is an explicit trusted input: its proof-system and
model-manifest digests must match the candidate before any commitment is used.

The sole non-standard Python dependency is the hash-pinned `blake3==1.0.8`
package already listed in `scripts/requirements-release-integrity.txt`.
