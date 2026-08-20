# ForgeMatrix custom proof protocol

Status: **research implementation; not a consensus proof tag**.

This document freezes the staged custom proof path that replaces the rejected
generic Remainder circuit experiment. The objective is a non-zero-knowledge,
transparent proof specialized for ForgeMatrix's banked matrix products and
local transition equations. No stage described here activates the production
profile by itself.

## 1. Acceptance rule

A production verifier must reject unless one canonical proof establishes all
of the following under the same transcript:

1. the exact network, algorithm, proof, model, and PCS parameter versions;
2. every block field, the chain-derived target, and the winning nonce;
3. the raw model identity and its linked polynomial commitment;
4. every matrix product in all three 128-layer banks;
5. every signed encoding, quotient/remainder equation, range, cubic output,
   and centered activation;
6. every successor edge, including the two bank boundaries;
7. the virtual input transition and terminal activation;
8. the final-activation digest and deterministic work digest; and
9. proof parsing, round, allocation, query, and verification-work bounds.

There is no fallback that accepts miner-supplied outputs, commitments, targets,
or digests when an opening or proof cannot be verified. Unknown proof versions,
timeouts, malformed transcripts, unavailable backends, and failed openings are
hard block failures.

## 2. Field and transcript

The structured sumchecks use the Goldilocks base field

```text
p = 2^64 - 2^32 + 1
```

and the cubic extension `Fp[u] / (u^3 - 2)`. An extension element is encoded as
three canonical little-endian `u64` coefficients. Every coefficient must be
strictly less than `p`. This gives roughly 192 bits of challenge space; the
implementation conservatively advertises 191 bits.

Fiat-Shamir challenges are rejection-sampled from domain-separated BLAKE3.
Each transcript item has a length-prefixed label and value. The transcript
absorbs the protocol version, public statement binding, exact dimensions and
integer bounds, commitments, claimed evaluations, every round index and
message, and terminal evaluations before its final digest.

The current research statement binding is an opaque byte string. The eventual
block proof must replace it with the canonical encoding of all public inputs
listed in section 1.

## 3. Bank-batched matrix sumcheck

For one power-of-two layer bank, let:

```text
X[l,r,k] = signed input activation
W[l,k,c] = signed model weight
S[l,r,c] = exact signed accumulator
```

Tables use row-major storage with the fastest MLE variable first:

```text
X point: [common bits, row bits, layer bits]
W point: [column bits, common bits, layer bits]
S point: [column bits, row bits, layer bits]
```

After the prover commits to `X`, `W`, and `S`, the transcript samples layer,
row, and column points `lambda`, `rho`, and `gamma`. The verifier claims
`S~(lambda,rho,gamma)`. The prover then proves

```text
S~(lambda,rho,gamma)
  = sum over l,k of
      eq(lambda,l) * X~(l,rho,k) * W~(l,k,gamma).
```

The common-dimension rounds have degree two. The layer rounds have degree
three because the layer selector, activation, and weight each depend on the
layer variable. One bank therefore needs `log2(D)` degree-two rounds and
`log2(L)` degree-three rounds, rather than one sumcheck per layer.

The terminal equation is

```text
claim = eq(lambda,l*) * X~(l*,rho,k*) * W~(l*,k*,gamma).
```

The two MLE evaluations must ultimately be authenticated by the transparent
PCS. The current `structured_sumcheck` research adapter instead receives the
complete tables and recomputes their hashes and openings. It reduces matrix
arithmetic but is not yet a succinct verifier.

The implementation now separates transcript verification from opening
authentication: `verify_structured_matrix_sumcheck` returns explicit
commitment, point, and evaluation claims, while the complete research adapter
accepts only after checking all three full-table openings. The transition
component uses the same boundary. These low-level claim functions are not
complete proof verifiers and must never be used without a PCS verifier.

### 3.1 Exact-integer condition

The matrix argument is a field identity. It represents the specified integer
identity only when canonical bounds exclude wraparound. For declared bounds
`A`, `W`, and `S`, the verifier requires

```text
D * A * W + S < p.
```

It also checks every value against its declared signed bound in the current
full-table adapter. Under this inequality, a field-zero difference between the
integer dot product and accumulator has magnitude below `p`, so the difference
must be the integer zero. A field congruence without these bounds is invalid.

For the proposed production values, `D=4096`, `A=125`, `W=125`, and
`S=64,000,000`, the bound is `128,000,000 < p`.

### 3.2 Current implementation result

`crates/cmfd-consensus/src/structured_sumcheck.rs` implements this complete
bank-batched matrix sumcheck. For the actual four-layer Devnet trace it has:

- two degree-two common rounds;
- two degree-three layer rounds;
- canonical 192-bit extension-field elements;
- a 556-byte encoded proof before PCS openings;
- strict proof and element caps;
- exact integer no-wrap checks; and
- mutation tests for statement replay, altered tables, altered rounds,
  noncanonical fields, truncation, and trailing bytes.

An incorrect accumulator causes proof construction to fail. Verification does
not repeat any dot products, but it still reads the full tables to check the
placeholder openings. The module is not wired into `BlockProof`, the wire
codec, `ConsensusPowVerifier`, or `ChainState`.

## 4. Transition sumcheck

The second custom component commits to banked oracles for the accumulator, mask,
signed-encoding flag, transition residue, both modular quotients and
remainders, output quotient and remainder, and centered activation. For every
cell it must enforce:

```text
e = s + mask + negative * P
e^2 = q2 * P + r2
r2 * e = q3 * P + r3
r3 = qo * 251 + ro
x_out = ro - 125
negative * (negative - 1) = 0
shifted_s = s + Smax
```

where `P=134,217,689`, all transition-field values are in `0..P-1`,
`qo <= 534,731`, `ro <= 250`, and `0 <= shifted_s <= 2*Smax < P`.
The signed accumulator is therefore unique as an integer rather than merely a
Goldilocks residue.

The mask oracle is separately identified with the authoritative affine mask
polynomial derived from the block challenge and layer number. The verifier can
evaluate that compact polynomial at the random MLE point from its per-layer
coefficients; it does not need a public mask table.

Ranges use base-16 value and slack decompositions. Each nibble
is constrained by

```text
d(d-1)(d-2)...(d-15) = 0.
```

All 121 local equations and range constraints are mixed with transcript-derived
coefficients after commitments, multiplied by an equality selector at a
random bank/cell point, and checked with one degree-17 sumcheck. The current
`structured_transition` implementation commits to 110 regular and digit
oracles and proves the actual four-layer Devnet transition trace in an
8,381-byte canonical transcript before PCS openings. In addition to the
transition-field ranges, it range-proves a shifted signed accumulator so the
matrix identity cannot be satisfied only modulo Goldilocks. It evaluates the
authoritative challenge-derived affine mask polynomial at the random opening
point, so a miner cannot substitute a convenient mask table. It rejects altered
quotient, sign, round, terminal, range, statement-binding, and encoding data.
As with the matrix component, its current full-table opening adapter is not a
succinct PCS.

The placeholder commitment is vector-content based rather than role based, so
the matrix and transition arguments produce the same commitment for their
shared accumulator oracle. An executable integration test locks that identity.
The eventual PCS must preserve this shared-oracle binding under one transcript.

A later reviewed lookup argument may replace this construction only if it
preserves the exact ranges and improves measured proof cost.

Successor wiring must prove every `X_out[l] = X_in[l+1]` edge and both bank
boundaries. Initialization and terminal activation are separate public
identities. Sampling cells or checking only selected layers is not acceptable.

## 5. Transparent PCS boundary

The PCS must support batched multilinear openings over the cubic Goldilocks
extension, deterministic canonical parameters, BLAKE3 commitments, and at
least 128-bit analyzed binding soundness. The model commitment is pinned at
network activation; winner-only trace commitments are block-specific.

WHIR is the current research adapter candidate because it supports batched MLE
openings, Goldilocks cubic-extension challenges, BLAKE3 Merkle commitments, and
provable decoding regimes. Its upstream Rust implementation explicitly labels
itself an unaudited academic prototype, so integrating it is evidence-gathering
work, not a production selection or audit substitute.

The PCS adapter must stream production model and trace data. Expanding every
model byte into an in-memory 32-byte field object, retaining duplicate encoded
matrices, or padding smaller trace tables to the 6 GiB model shape is an
automatic rejection for the 16 GiB target.

## 6. Soundness accounting

For one matrix bank, the raw sumcheck error is bounded by

```text
(2*log2(D) + 3*log2(L)) / |Fp^3|.
```

At `D=4096` and `L=128`, the numerator is 45. The final report must add all
three matrix banks. For one production transition bank, the degree-17
sumcheck has 26 variables (`7 layer + 7 row + 12 column`) and numerator 442.
Mixing 121 constraints with powers of one post-commitment challenge contributes
an additional polynomial-identity term with numerator at most 120. The final
report must also add wiring sumchecks, PCS binding/list-decoding error, hash
collision assumptions, and any proof-of-work grinding term. A machine-generated
report must show total error at most `2^-128`; quoting the extension-field size
alone is insufficient.

## 7. Miner shortcut boundary

The proof prevents acceptance of a false relation; it does not force a miner
to use the reference kernel, CUDA, tensor cores, a GPU, or physical VRAM.
Equivalent arithmetic, compression, tiling, and specialized hardware remain
valid. The seedless model, exact ranges, nonlinear transitions, and complete
layer binding are intended to remove known relation shortcuts, but the claim
must remain "no known bypass after review and testing," never "cheating is
mathematically impossible."

## 8. Remaining activation work

Before a production proof tag can exist:

1. implement and test the successor-wiring sumcheck and join the matrix and
   transition components under one PCS transcript;
2. integrate and harden a transparent PCS with canonical parameters;
3. link the raw model bytes to the pinned PCS commitment;
4. prove or replace the final BLAKE3 binding within the payload cap;
5. implement a bounded, panic-free proof parser and verifier queue;
6. demonstrate production-size streaming proving within the memory, proof-size,
   proving-time, and verification-time gates;
7. publish independent prover/verifier implementations and canonical vectors;
8. complete cryptanalysis, fuzzing, an adversarial testnet, and two external
   audits.
