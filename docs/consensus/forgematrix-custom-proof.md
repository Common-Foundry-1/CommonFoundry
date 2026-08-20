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

and the cubic extension `Fp[u] / (u^3 - u - 1)`, matching Plonky3's canonical
Goldilocks cubic extension. An extension element is encoded as
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

The same transition argument now covers the virtual input layer with
`layers=1`, an accumulator bound of 125, and the reserved mask-layer tag
`u32_le(0xffffffff)`. This proves the exact base-input reduction without
confusing it with real layer zero. Its input commitment is required to equal
the fixed base-table commitment; its activation commitment is linked to the
first matrix input by the wiring argument below.

A later reviewed lookup argument may replace this construction only if it
preserves the exact ranges and improves measured proof cost.

## 5. Successor-wiring argument

`structured_wiring` commits separately to each bank's matrix-input activation
table and transition-output activation table. Both use points ordered as
`[column bits, row bits, layer bits]`. The transcript samples one extension-
field cell point `c` and layer point `r` after all commitments.

For an `m`-bit layer axis, the multilinear extension of the output table with
its last layer removed is

```text
Xout(r,c) - product_j(r_j) * Xout(1,...,1,c).
```

The extension of the input table shifted left by one layer is

```text
sum for t=0..m-1 of
  (product for j<t of r_j) * (1-r_t) * Xin(d_t(r),c),
```

where `d_t(r)` fixes destination bits below `t` to zero, bit `t` to one, and
leaves higher bits equal to `r`. Equality of these polynomials checks all
within-bank successor edges; it is not a sampled subset of layers. Two more
fixed-layer identities compare each bank's final output with the next bank's
first input at the random cell point.

The proof also commits to the virtual transition's initial activation table.
At the same random cell point, it checks that table against bank zero's first
matrix-input layer. The production shape therefore needs 31 batched PCS
openings: ten per bank plus the initial-activation opening. Its canonical
wiring transcript is 1,036 bytes before PCS data. The actual one-bank,
four-layer Devnet trace uses six openings and a 308-byte transcript. The
current full-table adapter checks initialization and all successors exactly
and authenticates its placeholder openings by recomputation. Its research
element cap still rejects production tables.

The wiring proof's input commitment is required to equal the matrix proof's
activation commitment. The matrix accumulator commitment is required to equal
the transition proof's input commitment. The wiring output commitment is
required to equal the transition proof's centered-activation commitment. Its
initial commitment is required to equal the virtual transition's output
commitment, while that transition's input commitment is required to equal the
fixed base table. The aggregate public statement separately pins each model
weight commitment and the final bank-output commitment. Integration verifiers
and mutation tests enforce those identities under the same public statement
binding.

The aggregate v3 envelope no longer carries the row-major final activation
table. Its digest, deterministic work digest, target, challenge, model roots,
and length are committed into the public transcript binding before the wiring
cell challenge is sampled. A separate BLAKE3 STARK proves the exact derive-key
hash and proves that its private activation bytes have the same
cubic-Goldilocks multilinear evaluation as the PCS-authenticated last-layer
opening. The aggregate verifier accepts only when both the hash argument and
all PCS openings verify.

For larger tables, a custom narrow AIR authenticates every BLAKE3 chunk,
deterministic parent merge, root compression, counter, flag, chaining-value
edge, and final-table opening. Its schedule matches upstream derive-key BLAKE3
through the production 524,288-byte output shape. Its native transport removes
repeated Merkle paths into a canonical first-reference dictionary and then
uses canonical zlib compression under a 256 KiB component-envelope cap.
Release-mode vectors measure 165,039 bytes for a 64-byte activation and 222,555
bytes for a 2,048-byte multi-chunk activation. A 32,768-row checkpoint measured
233,382 compressed bytes (233,399 bytes with the outer envelope), about 12.22
GiB peak memory, and 266.25 seconds proving time.

The full production AIR has 1,048,576 rows and has not yet been proved end to
end. Its final size and resource use therefore remain activation gates. The
production-shape component uses a cubic Goldilocks challenge field and
machine-checks at least 128 proven bits under Plonky3's security model, but that
is not an aggregate union-bound report.
Independent algebraic review remains mandatory.

The main trace can now be emitted through a bounded row-at-a-time sink, and a
sink failure stops generation immediately. This is the required boundary for
a disk-backed consumer, but the pinned Plonky3 PCS API still requires an owned
`RowMajorMatrix` and materializes its LDE in memory. Replacing that PCS/FRI
stage, not merely streaming witness construction, is the remaining memory task.

## 6. Transparent PCS boundary

The PCS must support batched multilinear openings over the cubic Goldilocks
extension, deterministic canonical parameters, BLAKE3 commitments, and at
least 128-bit analyzed binding soundness. The model commitment is pinned at
network activation; winner-only trace commitments are block-specific.

WHIR is the current research adapter candidate because it supports batched MLE
openings, Goldilocks cubic-extension challenges, BLAKE3 Merkle commitments, and
provable decoding regimes. Its upstream Rust implementation explicitly labels
itself an unaudited academic prototype, so integrating it is evidence-gathering
work, not a production selection or audit substitute.

`structured_proof` now provides the fail-closed boundary for that integration.
It parses a canonical aggregate envelope capped at 5 MiB, validates component
counts and dimensions, checks every component transcript and cross-component
commitment identity, pins the base table and model weights, binds the declared
final bank-output commitment, canonicalizes and deduplicates all terminal
opening claims, and then requires both `StructuredPcsVerifier` and
`StructuredBlake3Verifier` to authenticate the complete claim set and final
digest. A missing, empty, malformed, oversized, conflicting, or rejected proof
is a hard error. There is no accept-without-verification path.

The optional `whir-prototype` feature now implements an accepting aggregate
research adapter beneath that boundary. It stacks bounded base-field tables
under one Plonky3 WHIR 0.6.3 commitment, exposes deterministic per-table
aliases, records caller-supplied points in the cubic Goldilocks extension,
builds their equality constraints directly, and verifies those exact points
through the lower-level WHIR verifier. It does not replace the independent
coordinates with the high-level layout's structured univariate-power points.
Its BLAKE3 transcript binds the public statement, all points and evaluations,
and the aggregate commitment before batching.
The prototype uses WHIR's non-conjectural unique-decoding parameter mode at a
requested 128-bit level. A 1 MiB proof cap, a 4 KiB public-binding cap,
canonical field checks, canonical JSON re-encoding, exact envelope exhaustion,
and panic containment bound its current parser surface.

The component proof constructors can now receive the WHIR aliases before any
component transcript samples challenges, and `StructuredWhirPcsVerifier`
authenticates the resulting aggregate claim set. The adapter still retains
whole bounded tables in memory and has no production model-byte link or
streaming 6 GiB prover. The upstream backend is an unaudited academic
prototype. Review, benchmarks, fuzzing, a complete soundness report, and
independent audits remain mandatory before any production selection.

The PCS adapter must stream production model and trace data. Expanding every
model byte into an in-memory 32-byte field object, retaining duplicate encoded
matrices, or padding smaller trace tables to the 6 GiB model shape is an
automatic rejection for the 16 GiB target.

## 7. Soundness accounting

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

The successor argument contributes numerator 135 for the production shape:
three 26-variable within-bank identities, two 19-variable bank-boundary
identities, and one 19-variable initialization identity. This is accounted
before PCS binding error and Fiat-Shamir grinding.

## 8. Miner shortcut boundary

The proof prevents acceptance of a false relation; it does not force a miner
to use the reference kernel, CUDA, tensor cores, a GPU, or physical VRAM.
Equivalent arithmetic, compression, tiling, and specialized hardware remain
valid. The seedless model, exact ranges, nonlinear transitions, and complete
layer binding are intended to remove known relation shortcuts, but the claim
must remain "no known bypass after review and testing," never "cheating is
mathematically impossible."

## 9. Remaining activation work

Before a production proof tag can exist:

1. harden and independently review the aggregate transparent PCS backend,
   canonical parameters, parser, and explicit-point transcript;
2. link the raw model bytes to the pinned PCS commitment;
3. run the exact BLAKE3 tree argument at the complete production shape and
   demonstrate that the full aggregate, not only the hash component, remains
   below its total payload cap;
4. fuzz the implemented bounded aggregate parser and add a bounded,
   panic-contained network verifier queue;
5. demonstrate production-size streaming proving within the memory, proof-size,
   proving-time, and verification-time gates;
6. publish independent prover/verifier implementations and canonical vectors;
7. complete cryptanalysis, fuzzing, an adversarial testnet, and two external
   audits.
