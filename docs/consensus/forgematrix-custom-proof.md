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

The BLS12-381 backend uses transcript version 2. Its sampler accepts a 256-bit
little-endian candidate only when it is the canonical encoding of a nonzero
scalar, otherwise it derives another candidate with a counter. Accepted
challenges are therefore exactly uniform over `Fr*`; algebraic error terms use
the denominator `|Fr|-1` without modulo-reduction bias.

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
bytes for a 2,048-byte multi-chunk activation. With a log-size-seven final
polynomial, an isolated 32,768-row checkpoint measured 209,693 compressed bytes
(209,710 bytes with the outer envelope). That configuration has not yet been
timed; the earlier final-polynomial-zero run used about 12.22 GiB peak memory
and took 266.25 seconds.

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

### 5.1 Optional GPU prover work

The feature-gated prover can explicitly replace Plonky3's CPU
`TwoAdicSubgroupDft` with a CUDA implementation of the same Goldilocks DFT and
coset-LDE semantics. Natural and physical bit-reversed row layouts, inverse
transforms, transformed coefficient callbacks, canonical field
representatives, and dimension caps are checked at the Rust/C ABI boundary.
The production-shaped `32,768 x 291`, `+7` coefficient LDE produces a
`4,194,304 x 291` output without constructing the expanded matrix on the host.
On an RTX 5090 it measured 371.748 ms of device work and 482.986 ms end to end
to a device-resident result, excluding device-to-host transfer. That canary
deliberately left the 9.094 GiB result on the device. These are kernel-path
measurements, not a complete production proof benchmark.

In an unoptimized Cargo test-profile comparison at the same 32,768-row shape,
the CPU path took 348.28 seconds of wall time: 64.503 seconds of preprocessed
setup, 283.416 seconds in the prover, and a 238,698-byte canonical zlib payload.
The wired CUDA DFT plus Poseidon2 path took 76.71 seconds: 7.700 seconds of
setup, 68.551 seconds in the prover, and a 237,292-byte payload. This is a 4.54x
speedup and 78% less wall time on the RTX 5090. These test-profile numbers are
not directly comparable to the release-mode checkpoint above. The unchanged
CPU verifier accepted the accelerated proof.

The prover-side Poseidon2 first digest layer used by the value MMCS is now wired
into proof generation. Its exact CUDA ABI matches the pinned Plonky3
`PaddingFreeSponge` for concatenated rows from one or more matrices. At
4,194,304 rows on the same RTX 5090, width 291 measured 202.013 ms of kernel
time; host-to-device transfer of the 9.094 GiB input measured 732.967 ms. The
CUDA result feeds the ordinary Merkle tree; parent compression,
shorter-matrix injection, openings, transcript operations, and verification
remain on the CPU.

The monolithic Poseidon2 ABI v1 remains test-profile-only. The separate
`proof_stream` ABI v1 copies up to 64 ordered, equal-height canonical
physical-bit-reversed coefficient matrices to the selected device once, with a
maximum `2^20` source height, seven added bits, `2^27` output rows, 4,096 total
columns, and `2^31` input limbs. `next` accepts a monotonic global physical-row
cursor and a power-of-two request no larger than `2^16` rows that may not cross
a source-height coset block. It returns an optional interleaved physical LDE
chunk and the required four-limb, unpadded Poseidon2 digest for each row. CPU and
GPU differentials cover distinct per-matrix shifts, insertion order, chunk
partitions, and the exact Plonky3 commitment input.

For the `32,768 x 291`, `+7` case, the digest-only stream phase processed all
4,194,304 rows in 308.345 ms, or 13.60 million rows/s, on an RTX 5090 while
avoiding a 9.094 GiB host LDE. This is a bounded CUDA canary measurement, not a
complete proof benchmark.

The worker-side LDE artifact writer accepts canonical chunks only at the exact
next global physical row. Its versioned header binds the job identifier, every
ordered source-matrix width and coset shift, source and expanded heights,
aggregate width, added bits, physical layout, and byte length; BLAKE3 covers
that metadata and every canonical little-endian field limb. Normal error and
drop paths remove an incomplete `.partial` file, while abrupt process
termination can leave an unpublished partial for operator cleanup. Only a
complete, synchronized, validated artifact is published without overwrite.
A reader validates the header, exact file length, and full checksum when
opening it, then reauthenticates every fixed-size chunk used by random row
access. These digests protect spill storage integrity;
consensus validity still comes from the unchanged proof verifier.

The stream and sealed artifact do not yet make Plonky3 consume disk-backed
matrices. Full out-of-core PCS and FRI processing, Merkle-level construction
and storage, and query opening generation remain incomplete. Production uses
`2^27` LDE rows; widths 291 and 87 still imply 291 GiB and 87 GiB logical LDE
matrices, and the first digest layer alone is 4 GiB. This milestone is not a
production-ready prover.

The CUDA library is native code and is never trusted for validity. The direct
accelerated entry point loads it in-process, is restricted to trusted
development, and verifies the complete encoded proof with the unchanged CPU
verifier. A caller can instead use the separate short-lived worker, which adds
bounded canonical IPC, SHA-256 pins for both artifacts, deadlines, output
limits, and process-tree termination. That worker path has been tested with a
64-byte tree proof. It contains ordinary crashes but is not a same-user
security sandbox; production deployment still needs OS-enforced isolation and
artifact custody.

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

The optional `whir-prototype` feature now implements an accepting split
research adapter beneath that boundary. `ModelPcsIdentity` freezes the model
version and shape, model byte root, centered-byte field encoding, MLE axis
order, exact WHIR suite/parameter digest, base-input commitment, and ordered
weight-bank commitments. The model-bank manifest retains its 184-byte format:
its existing PCS parameter digest and commitment root must match this separately
supplied identity. The aggregate verifier receives that identity from its
trusted caller and rejects statement-level root, base commitment, weight-bank,
bank-order, and model-shape substitutions before component algebra. The scoped
PCS verifier separately rejects a substituted split-envelope root or table
layout when it authenticates the collected openings.

The WHIR adapter commits each fixed model role independently and places all
challenge-specific trace tables under a separate commitment. A new versioned
split envelope carries one opening proof for the base table, one for each
ordered weight bank, and one for the execution trace. A common BLAKE3 transcript
binds the public statement, complete model identity, every fixed root, and the
trace root before scope-specific child transcripts are derived. Fixed-model and
trace opening claims are canonicalized separately and cannot share commitment
identifiers. The adapter records caller-supplied points in the cubic Goldilocks
extension, builds their equality constraints directly, and verifies those exact
points through the lower-level WHIR verifier. It does not replace the
independent coordinates with the high-level layout's structured
univariate-power points.

The prototype uses WHIR's non-conjectural unique-decoding parameter mode at a
requested 128-bit level. The native research payload has a 1 MiB parser cap;
its 20-byte standalone envelope also refuses any encoding that would exceed
the 256 KiB network proof budget after the 16-byte outer wire header. The
structured split aggregate has a 512 KiB PCS-proof cap. A 4 KiB public-binding
cap, canonical field checks, configuration-derived vector shapes, exact
envelope exhaustion, and panic containment bound the current parser surface.
Native proof v2 uses a manual fixed-width little-endian codec; it does not
accept legacy JSON, zlib, bincode, varints, trailing bytes, or
attacker-selected semantic vector lengths. Its untrusted dictionary count is
strictly bounded by both the exact input length and the fixed proof cap.

For bounded research artifacts, `from_verified_model_bank` now closes the
previously separate byte-root and PCS-table inputs. It accepts an externally
trusted manifest and full model identity, rejects unsupported table dimensions
before reading, buffers no more than the trusted fixture length plus one byte,
and runs the canonical model-bank verifier over that immutable buffer. Only
after the header, byte range, raw root, indexed layer roots, exact length, and
EOF checks pass does it map each byte through the pinned `x - 125` Goldilocks
encoding, preserve base/layer/bank order, derive the base role and every ordered
weight-bank role, and require byte-for-byte equality with the trusted PCS
identity. Callers cannot supply parallel field tables or a replacement byte
root through this path.

The model-bank layer also exposes a one-pass staged field stream for the next
out-of-core checkpoint. It accepts the full externally trusted PCS identity,
derives the bank partition from that identity, reads one already-open source
without seeking or reopening it, and feeds base input followed by ordered
weight banks as canonical centered Goldilocks `u64` chunks. One fixed 64 KiB
byte buffer and one fixed 64 KiB field buffer bound its working memory. The
current 184-byte format authenticates the complete payload rather than each
prefix, so sink writes remain provisional: the sink receives an unforgeable
completion receipt and may publish only after the raw root, indexed layer-root
aggregate, exact payload length, and EOF all match. Reader and sink failures
abort before that publication barrier.

The BLS12-381 sink now uses that same publication barrier to build one
self-authenticating coefficient artifact for the base input and each ordered
weight bank while computing the corresponding Dory row and tier-two
commitments. No polynomial or identity is returned unless the full model bank
authenticates. Corrupt and trailing inputs clean every provisional artifact.
The matrix prover consumes a precommitted weight artifact sequentially to form
its random-column partials, reuses the same artifact in the shared aggregate
opening, and checks its commitment against the pinned bank role before proving.
Bounded fixtures produce the exact materialized proof and reject a substituted
bank commitment. At production geometry this removes the roughly 16 GiB
materialized `i64` slice per bank; the required canonical scalar artifact is
still roughly 64 GiB per n=31 bank and its complete preparation/proving latency
and peak disk use remain unmeasured.

The feature-gated WHIR sink now writes
one authenticated source artifact for the base input and each ordered weight
bank. It seals them in an unpublished attempt directory, binds their exact digests,
roles, expected commitment aliases, model identity, and manifest into a
canonical bundle, and publishes one no-overwrite hard-linked manifest pointer
last. Concurrent identical publishers converge; a process crash before the
pointer can leave unreachable objects but cannot expose a partial bundle.
The builder also returns a canonical 108-byte bundle identity that must be
retained outside the publication tree. Reopening checks that independent
identity before trusting any artifact digest from the replaceable pointer, so
a self-consistent pointer-and-object substitution fails closed. Before reading
the model, publication preflight exercises the actual staging-to-object and
object-to-pointer-parent hard-link edges without deleting pre-existing files.
Hard-link namespace updates are not portably directory-synchronized on every
supported Windows/Linux filesystem, so sudden power-loss durability is not yet
claimed; reopening fails closed if any object is missing. Killed attempts can
also strand up to roughly 48 GiB under staging, and content-addressed objects
created by a losing publication can be unreachable. Production operation still
needs lock/lease-aware stale-attempt and unreferenced-object recovery that never
deletes a live concurrent publisher.

This closes the raw-model-byte-to-authenticated-WHIR-source boundary. The
source bundle alone does not establish the role's expected WHIR commitment.
`PublishedModelWhirSourceBundle::into_roles` transfers the already authenticated
source handles into later preparation without another reopen or proportional
rescan; the typed role join below closes the later source-to-initial-commitment
identity boundary only after an authenticated codeword and typed initial demand
tree have been built.

The proof-acceleration crate has two bounded external-memory encoders for the
initial suffix-order WHIR codeword. The reference encoder admits at most 19
table variables and covers the proposed production `2^18 x 4` base-input
codeword. A distinct exact-31-variable six-step encoder consumes only an
authenticated 31-variable source artifact, preserves the frozen `CMFDWIH1`
bytes, and accepts exactly 31 variables. Its underlying generic six-step
transform matches the reference encoder byte-for-byte at 5, 9, and 17
variables. The nonallocating plan pins a 17,188,257,952-byte source artifact, a
34,493,956,256-byte codeword artifact, a 68,719,476,960-byte initial demand
tree, 120,401,691,168 persistent bytes for one source/codeword/tree artifact
set, 68,719,476,896 bytes of encoder scratch/output space, and 269,484,032
bytes of requested transform-buffer payload. No complete 31-variable run or
production timing benchmark is claimed.

The exact-31 encoder also has a controlled entry point for operator progress
and cooperative cancellation. It reports deterministic logical bytes, rather
than physical I/O or elapsed-time estimates, across transpose, first FFT,
second FFT, sealing, and complete verification; a stage reaches 100 percent
only after its durability or checksum boundary succeeds. Cancellation is
checked between bounded authenticated reads, transform work units, writes, and
verification batches, unwinds through ownership-checked staging cleanup, and
never publishes a partial result. The final cancellation check occurs before
the no-overwrite hard-link publication barrier. Once that barrier begins, the
observer is not called and cancellation is ignored until the indivisible
hard-link, directory-sync, staging-removal, and directory-sync sequence either
succeeds or returns an error. Cancellation discards the attempt; resumable
checkpoints remain separate future work.

The original natural-order table is stored in its own authenticated source
artifact, whose separately retained whole-artifact digest is the provenance
check; `source_id` remains only a cross-artifact label. The independently
versioned initial demand-tree suite is fixed at width four, admits power-of-two
heights from `2` through `2^30`, and derives its codeword binding from the
complete authenticated codeword identity rather than a caller-supplied digest.
The V2 oracle and prover identities admit 2 through 31 variables and bind the
exact codeword, typed tree, caller context, and source-artifact digest.
`adopt_published_model_whir_role_v2` consumes one published role, codeword, and
tree; checks the trusted suite, role, source identity, and geometry; derives the
existing one-table structured commitment alias from the tree root and variable
count; requires that alias to equal the role and `ModelPcsIdentity` commitment;
derives a versioned role context; and returns a `PreparedModelWhirRoleV2`. Only
the ordinary Merkle root enters the unchanged WHIR transcript. The join performs
no encoding and raises no proof-size or variable limit.

Three production weight sources occupy about 48 GiB. Sealing currently rereads
each artifact twice for staged and published verification, and the builder's
immediately anchored bundle reopen performs a third full read. Authentication
digests are accumulated during the one-pass write, so the former pre-seal data
scan is gone, but a complete build still performs about 48 GiB of verification
reads per 16 GiB role, or about 144 GiB across all three. `into_roles` prevents
a further reopen/rescan before the typed join. Reusing an authenticated handle
across same-inode hard links remains a ceremony-throughput optimization.

The initial fold-two sumcheck also streams that source in chunks of at most
8,192 canonical `u64` values. It keeps four suffix partials per claim. An
explicit scratch-directory path now writes the resulting `N/4` evaluation and
weight pairs to a dedicated ephemeral artifact in natural suffix order. Every
row contains six canonical little-endian Goldilocks limbs: three for the cubic
extension-field evaluation and three for its weight. A caller-retained source
capability digest and a separate digest of the suite invocation, ordered
claims, alpha, both sumcheck messages, optional grinding witnesses, challenges,
and post-fold claim bind the artifact locally. Neither digest, the file path,
nor any storage metadata enters Fiat-Shamir.

The writer uses bounded chunks, checked 64-bit geometry, free-space preflight,
no-overwrite same-directory publication, complete BLAKE3 authentication, and
per-chunk reauthentication on later reads. Normal successful consumption
checks that the current path still names the owned open file before removal.
Failure and unwind cleanup is best effort, so killed attempts or deletion
failures can strand a large scratch file and production operation needs
ownership-aware stale-attempt recovery. The generated filenames must remain an
exclusive, access-controlled local scratch namespace while proving: the
portable identity check and pathname unlink are not a single atomic filesystem
operation. At the production
31-variable source shape, the fixed two-variable fold gives `2^29` residual
rows. The paired artifact is exactly 24 GiB of field data plus 2 MiB of chunk
digests and a 160-byte header; this geometry is tested without allocating the
rows.

Exact tests match the dense commitment, openings, transcript, and serialized
proof bytes at 2, 8, and 9 variables. A 17-variable initial-sumcheck test has a
`2^15`-row residual, crosses Plonky3's parallel coefficient threshold, and
matches every message, challenge, evaluation, weight, claimed sum, and next
transcript sample. Completed proofs still pass the unchanged CPU verifier, and
an injected source failure after artifact creation leaves no partial file or
dense fallback.

The vendored WHIR prover now exposes a fallible state boundary after the
initial sumcheck. Its dense adapter preserves complete prefix- and
suffix-layout proof bytes and the next transcript challenge. Injected failures
at extension commitment, OOD evaluation, Merkle opening, sumcheck, and final
polynomial materialization return without a retry or dense fallback; the
caller must discard the partially advanced proof and challenger. The Common
Foundry spill entry point now implements that boundary with an artifact-backed
state. It scans the residual in chunks of at most 8,192 rows, adopts exact
disk-backed extension commitment identities, authenticates requested Merkle
paths, and writes each folded child residual incrementally. Only the final tail
of at most six variables is materialized densely. Constraint equality and
selector weights are generated per chunk, and every post-fold dot-product and
row-count invariant is checked before the parent artifact is replaced. Any
state or storage error poisons the attempt and cannot fall back to the dense
state.

An exact authenticated reference encoder now covers the next extension
codeword. It groups four residual evaluations into four cubic-extension
elements, stores their twelve canonical Goldilocks limbs per row, and matches
Plonky3's suffix-order extension DFT and BLAKE3 MMCS leaves. At the production
`2^29`-row, log-rate-two geometry the codeword is exactly 48 GiB plus 2 MiB of
chunk digests and a 288-byte header. The identity binds the complete residual
identity, folding and rate parameters, geometry, caller context, and final
artifact digest. Reopen, random reads, publication, and cleanup fail closed on
identity substitution, corruption, truncation, append, or path replacement.

That encoder deliberately refuses execution above `2^20` rows before reading
the source or creating a file. Its bounded fused radix-2 engine removes the
large retained twiddle tables and matches exact bytes, but the modeled `2^29`
run with the current 512-row buffer would still make 21 complete read/write
passes: about 1.97 TiB of traffic and 44 million read/write calls. The legacy
format-v1 BLAKE3 store authenticates the complete artifact when it is opened
and remains capped at `2^18` rows; the spill prover no longer selects it for
extension commitments.

A separate format-v2 demand-authenticated tree stores only the exact Plonky3
layer-major digests. At `2^29` rows it is 34,359,738,592 bytes. Reopening checks
the fixed identity envelope without a proportional scan, and each opening
reads one sibling per layer and reconstructs the independently pinned root
against the separately authenticated 96-byte extension row. Publication is
no-overwrite and directory-synchronized on supported Windows and Unix
filesystems. This format reaches production geometry as a storage component,
and the artifact-backed WHIR state now adopts it through the joined extension
oracle. Retained codeword and tree identities are rechecked on adoption and
every opening; each child residual binds every field of both identities in its
local lineage. Combined extension-and-tree space is checked before either
artifact is created. The worst checked geometry is 51,541,704,992 bytes for the
extension plus 34,359,738,592 bytes for the tree, or 85,901,443,584 bytes total,
and that preflight allocates no row-proportional memory.

The artifact state has exact commitment, opening, and next-challenge parity at
9, 13, and 16 variables, multi-chunk constrained-fold parity at 16 variables,
and complete proof-byte parity at the bounded end-to-end fixtures. The
unchanged verifier accepts those proofs. The former public 13-variable JSON
encoding was 1,236,482 bytes, of which 99.5 percent was the 794 query openings
and their 8,606 authentication nodes.

Native proof v2 replaces that transport with a 40-byte versioned header,
fixed-width canonical Goldilocks limbs, and a `u16` dictionary ordered by each
Merkle node's first use. Every query count, value width, path depth, sumcheck
round, option, and PoW field is derived from the trusted `WhirConfig`. The
decoder rejects duplicate or reordered dictionary entries, forward or unused
references, noncanonical limbs, ignored nonzero PoW fields, wrong query
variants, truncation, and trailing bytes before calling the unchanged verifier.
It also rejects a dictionary larger than the exact per-tree-level maximum
derived from the trusted query and path geometry. This stricter grammar is an
inner-codec v2 hard cutover and changes the committed WHIR suite identity. It
uses no general-purpose compression.

Across ten deterministic 13-variable transcripts, native bytes measured
188,084 through 190,004 and the standalone explicit envelope measured 188,104
through 190,024 bytes (about 183.7 through 185.6 KiB). The worst vector
retains 72,104 bytes below the 256 KiB wire cap after including the 16-byte
outer wire header. All ten native lengths are pinned by tests. The first native
vector is 188,148 bytes with BLAKE3 digest
`b2a4ae88c9fbf7d1fe9056abf546429d1a88162b30b257c7968f7ea8777c852c`.
Independently of those samples, the binary-tree geometry limits verifier-valid
13-variable authentication paths to 4,011 distinct dictionary nodes. That
gives a conservative maximum of 203,540 native bytes, or 203,576 bytes with
both envelopes, leaving 58,568 bytes of transcript-independent headroom.
Real prover/decoder/verifier round trips cover 2, 8, 9, and 13 through 16
variables; configuration-derived synthetic codec round trips extend through
the structured adapter's 20-variable limit. The research prover and verifier
continue to exercise 15- and 16-variable proofs, but their standalone encoder
returns `ProofTooLarge`; those shapes are not represented as wire-ready.

This result is one direct WHIR proof, not the complete production block proof;
the split PCS envelope contains multiple child proofs and the aggregate also
contains the arithmetic and BLAKE3 arguments. Exact 31-variable codeword
construction, the typed initial demand tree, V2 oracle identities, and the
typed role join now cover initial artifact preparation, but they do not make a
31-variable proof executable. The public explicit prover/verifier remains
capped at 16 variables. The opt-in `production-whir-candidate` profile now
derives a separate suite and canonical parser geometry for the exact n=19 base
and n=31 weight roles while leaving V2 unchanged. The measured n=19 native
dictionary-free floor is 133,298 bytes; n=31 is 268,640 bytes before any Merkle
dictionary, exceeding the complete 262,128-byte proof payload by 6,512 bytes.
The candidate therefore rejects n=31 before proof decoding or proof-sized
allocation. The reference extension-codeword encoder also remains capped at
`2^20` rows. Production now requires a smaller proof geometry or
aggregation/compression design, a byte-identical blocked or GPU extension
transform, and complete production execution and benchmarks.

The ordered execution trace now has an exact 439-column batching model: 109
initialization transition columns and three banks of 110 transition columns.
Padding those columns to 512 slots adds nine selector variables over a shared
26-variable local domain. Executable geometry rejects both direct transports.
Thirteen independent section proofs have a 3,365,110-byte dictionary-free
floor. Even selector-first folding would spend 1,085,208 bytes on first-round
semantic field values alone (1,265,664 bytes with canonical slot padding),
before roots, authentication paths, headers, or sumcheck messages. Keeping the
ordinary two-variable local fold raises those figures to 4,340,832 and
5,062,656 bytes. A bounded
four-column reference test commits the stacked polynomial, folds its selector
variables, continues the residual into one WHIR proof, and verifies it on the
CPU; substituted evaluations, reordered or missing columns, and transcript
replay are rejected. The production row-fold primitive separately enforces all
439 semantic slots, 73 zero slots, and the smaller initialization domain. This
establishes the algebraic handoff, not the missing succinct vector-commitment
opening needed to fit the complete production proof below 256 KiB.

An exhaustive trace-specific schedule checkpoint now separates wire geometry
from soundness assumptions. Folding all nine selector variables first leaves
26 local variables, so Goldilocks' 32-bit two-adicity caps the starting
log-inverse rate at six. The 262,128-byte native payload could contain at most
63 initial 512-value openings even if every other proof byte were free. At the
requested 128-bit unique-decoding setting, the pinned WHIR derivation needs 131
queries with no grinding, or 115 under the practical 16-bit grinding ceiling:
536,576 and 471,040 base-field value bytes respectively. Reaching 63 queries
requires at least 67 configured grinding bits, which is not an operational
prover.

Two smaller comparison schedules are deliberately not promoted. CapacityBound
has a 193,444-byte conservative maximum with zero derived grinding, but that
mode explicitly conjectures Reed-Solomon decoding and mutual correlated
agreement up to capacity. JohnsonBound has a 239,616-byte conservative maximum
only with 48 configured and derived grinding bits. The production policy
therefore remains non-conjectural unique decoding and fails closed. The
vendored WHIR constructor also now rejects a later folded domain above the
base field's two-adicity instead of reaching an asserting field-generator call;
the same guard covers the final fold.

The implemented successor attacks width rather than soundness. Of the 110
transition oracles, 12 carry algebraic values and 98 are paired base-16 digits
for eight value/slack range checks. Initialization retains 11 core columns
because its input is fixed; the three banks retain 12 each, for 47 ordered core
columns. The first V1 range layout transposed each cell into 49 active plus 15
zero rows with four witness columns. Exact FRI accounting rejected that layout:
its bank trace is `n=32`, but log blowup four needs an `n=36` LDE, beyond the
Goldilocks field. The V1 digest
`6c7ccc9e63cae28907ae173372ddf33a3526f2ea2cc46b514510e4b330082769`
therefore pins a no-go checkpoint, not an activation candidate.

V2 packs two range specifications into each of four rows per cell. It uses 28
digit columns split among seven four-query nibble buses, plus seven fixed-table
multiplicity columns. The active digit counts per row are `[28, 28, 24, 18]`;
unused slots are canonical zero. Lookup IDs, source oracles, bounds, digits, and
selectors are verifier-derived. Main widths are 46 for initialization and 47
for a bank. Initialization is `n=21`, each bank is `n=28`, and the log-four LDE
is exactly `n=32`. Canonical generation, reconstruction, padding, and column
order are committed under digest
`88f2f31f6f9d4aca4a69bc2ac6dfd88bcf670c3ed803e0fb24a241f791372cb3`.
The reusable preprocessing plan has width 66 and explicitly contains no
challenge-dependent mask column. Its selector/table prefix is followed by 7
layer, 7 row, and 12 column bits. Its initialization and bank structural
digests are
`5b2b1251538d96ebc8eb5a9f3a6ecdb314a3de73d15b3ef60643db84af84811e`
and `c5c2d698f1cbdf016d5272ec4c574314fef63653ebeb62e460bb45b11640fa75`;
actual pinned PCS roots remain to be generated.

The first batch-STARK reduction for V2 is executable on a 128-cell, 512-row
fixture. The AIR folds a 128-layer padded coefficient table with the seven
authenticated layer bits, combines the selected affine coefficients with the
row and column bits, and enforces the resulting challenge-derived mask. It also
enforces the encoded input,
square reduction, cube reduction, output reduction, centered activation,
negative-bit, and shifted-accumulator equations. Eight source buses bind every
`(lookup ID, source, maximum - source)` tuple. Seven nibble buses each bind four
packed digit columns to the verifier-fixed `0..15` table. The pinned AIR has
maximum degree nine, 145 constraints, three quotient splits, and 48 base-field
lookup auxiliary openings at each local and next evaluation.

With log blowup four and 57 configured FRI queries, the library's executable
estimator reports 128 list-decoding bits; 56 is the first query count reaching
that target for both the fixture and production trace size. A
separate root count covers same-bus and cross-bus beta collisions, false
rational sums, and all denominators under the single shared `(alpha, beta)`
pair. Its 288,388,719 roots over the cubic Goldilocks extension give an error
below `2^-163`. The 512-row fixture serializes to a 222,960-byte fixed-width
bincode baseline. Repeated best-zlib runs measured 160,461 to 160,667 bytes;
tests enforce a 165,000-byte ceiling. These are diagnostic fixture sizes, not the
production native codec or production-shape bound. Tests mutate every core column and reject changed arithmetic,
mask, active digits, padding, table multiplicities, lookup topology, table
values, and untrusted degree vectors. This remains test-only: that FRI transport
still needs exact initialization input, actual pinned preprocessing roots,
native canonical encoding, aggregate size and latency measurements, and verifier
integration. The scalar Dory path below separately implements the
cross-component wiring equalities.

The executable wire budget also rejects ordinary batch-STARK FRI as the
production transport for this reduction. At the production bank geometry the
trace has 28 variables, the log-four LDE has 32, and the six folding rounds
have log arities `[4, 4, 4, 4, 4, 1]`. A valid 57-query transcript whose queries
occupy distinct six-bit prefix buckets at every committed fold forces 4,275
distinct authentication nodes below those prefixes. Even with one globally
deduplicated Merkle dictionary, query inputs, FRI siblings, out-of-domain
values, the final polynomial, and those nodes total at least 333,792 bytes.
That exceeds the 262,128-byte native budget by 71,664 bytes before commitment
roots, proof-of-work witnesses, lookup terminals, input commitment paths, or
headers. Rejecting that transcript shape would turn proof size into another
Fiat-Shamir grinding condition. The compact arithmetic and range reduction is
therefore retained, but a different succinct commitment or aggregation layer
is a production requirement.

The next transport checkpoint is an off-by-default Dory aggregation prototype.
It uses a degree-two multilinear sumcheck to reduce ordered openings at distinct
points to one random point, then combines the polynomials, tier-one rows, and
tier-two commitments with the final equality-polynomial weights and produces a
single homomorphic Dory opening. The wrapper transcript binds the setup identity,
block statement, exact matrix shape, every ordered commitment, every point, and
every evaluation before sampling batching challenges. It also binds the combined
opening because the upstream API does not absorb that public statement.

The prototype wire parser is fixed-shape: before Dory deserialization it checks
the total length, round count, transparent final-message flag, and `nu`/`sigma`,
then validates group encodings, reserializes canonically, and rejects trailing
bytes. An n=8 three-claim fixture is exactly 12,063 bytes. Using compressed
BLS12-381 element sizes, the same n=31 grammar projects to 66,559 bytes for this
sumcheck and opening aggregate. This is not a complete production proof-size
claim. That original module remains a BN254 reference with random setup vectors,
and its production gate always returns an error. A separate
`dory-bls12-381-prototype` feature now implements the generic Dory field, group,
pairing, polynomial, and transcript adapters on BLS12-381. It deterministically
derives role-separated setup points with IETF hash-to-curve, binds the complete
setup to a pinned BLAKE3 identity, and produces and verifies a real n=8 opening.
Its canonical compressed Dory payload is 16,909 bytes. The BLS aggregate now
executes the same distinct-point reduction for three n=8 claims and emits a
17,695-byte canonical proof including the eight sumcheck rounds and fixed
header. Its parser preflights the complete shape before group decoding and
rejects malformed lengths, trailing data, statement or claim reordering, mixed
setup identities, and mutated sumcheck or Dory bytes. The implemented n=31 wire
projection is 66,559 bytes, below the 262,128-byte payload cap, but the in-memory
prover remains capped at n=16. This executable checkpoint confirms the curve,
setup, aggregation, and codec route; it is still a sequential, unaudited
reference and is not connected to consensus.

The matrix checkpoint keeps activation, model-weight, and accumulator tables in
three distinct commitments. Each table is zero-padded only in high variables to
the largest table geometry, preserving its natural MLE coordinates while giving
the Dory aggregate one layout. It executes the exact degree-two common rounds
and degree-three layer rounds from Section 3, then authenticates the activation,
weight, and accumulator evaluations together. The executable n=3 fixture is
11,539 bytes, including a 9,439-byte three-opening aggregate. A fixture with
unequal activation, weight, and accumulator geometries verifies the high-zero
padding rule. The production weight table is n=31; its complete matrix grammar
projects to 70,483 bytes, including 66,559 bytes for the aggregate, and its raw
sumcheck error numerator is 45. The parser derives both round counts and every
round degree from the trusted statement before group decoding. The shared path
now checks the weight commitment against a trusted BLS fixed-model identity
bound to `ModelPcsIdentity`, and links the activation and accumulator commitments
to the wiring and transition components. The authenticated model-bank reader now
drives an incremental Dory commitment sink in exact base-input and weight-bank
order. It retains only a bounded field chunk and one partial row, and it cannot
publish the BLS identity until the trusted roots, exact payload length, and EOF
verify. Its executable fixture matches the existing in-memory commitment path
exactly and rejects corrupted, trailing, reordered, or noncanonical input. The
final production artifact still must be run through the n=33 setup to publish
the actual network-pinned commitments.

The transition checkpoint now goes beyond field-portability tests. It packs the
110 canonical transition oracles into 128 selector slots under one Dory
commitment, but its arithmetic sumcheck folds only the twelve regular roles.
Seven local arithmetic constraints produce degree-three rounds, and twelve
terminal evaluations are authenticated as distinct points of the packed
commitment. Range membership and reconstruction are delegated to the scalar
range checkpoint below. The composed verifier requires both proofs to carry the
exact same commitment. No witness table is supplied to verification. A bounded
canonical outer parser preflights the statement-derived round count, terminal
count, opening length, and complete byte length before decoding curve elements,
then re-encodes the arithmetic proof canonically. The executable 2x2x2-cell
fixture packs to n=10 and is 23,171 bytes, including a 21,775-byte Dory opening
aggregate. A production bank has 26 cell variables plus seven selector
variables; the n=33 arithmetic grammar projects to 74,979 bytes, of which
70,639 bytes are the opening aggregate. This is size accounting, not a
production-scale proving result.

The successor-wiring checkpoint uses the same scalar field and Dory backend. It
packs the initial activation table and up to three input/output bank pairs into
eight selector slots under one commitment. Challenges sampled after that
commitment reduce every within-bank successor edge to the exact shift identity
from Section 5, while fixed first/last-layer openings enforce initialization and
both bank boundaries. A single distinct-point aggregate authenticates all of
those evaluations. The executable two-bank, two-layer fixture packs to n=6 and
is 14,529 bytes with nine openings, including a 13,615-byte Dory aggregate. The
production table has 26 table variables plus three selector variables and needs
31 openings; its n=29 grammar projects to 64,097 bytes, including 62,479 bytes
for the aggregate. The verifier receives no activation tables. Its canonical
parser preflights the statement-derived variables, evaluation count, opening
length, and total length, and mutation tests cover every evaluation role.
The shared layout below now supplies equality links from the scalar matrix and
packed transition commitments to these wiring roles.

The shared-layout checkpoint removes a prerequisite mismatch between these
three components. Each prover and verifier can now be given an exact common
variable count, with only high-zero padding above the component's natural table
geometry. That padding preserves the original multilinear coordinates. The
canonical outer decoders require the same exact count and reject a different
layout before invoking Dory verification. In the executable n=10 integration
fixture, matrix, arithmetic transition, range, and wiring all prove and verify
at that one geometry. The linked fixture has 56 openings, one 21,775-byte Dory
payload, and a complete 35,989-byte canonical frame. The parser derives
every component shape from trusted statements and rejects malformed lengths,
trailing bytes, omitted components, and incompatible geometry.

Production is pinned to the maximum component geometry, n=33. One Dory opening
payload at n=33 projects to 70,639 bytes, but direct composition would expose 9
matrix claims, 440 transition claims, and 31 wiring claims: 480 total, which
exceeds the current 128-claim aggregate bound. That direct composition cannot
be aggregated within the bound and is why the range compression below is
required.

The scalar range bridge now proves digit membership and radix reconstruction
against that same transition commitment. The prover commits the sixteen
`0..15` table multiplicities before sampling `alpha`, derives and commits one
inverse polynomial afterward, and runs a degree-four sumcheck over inverse
correctness, support, rational-sum, and total-count identities. The verifier
derives the active digit-selector and fixed table polynomials itself. This
membership portion terminates in three openings: transition digit,
multiplicity, and inverse.

After those terminals are transcript-bound, the verifier samples a random cell,
a random three-bit range-spec point, and a slack-mixing scalar. It then samples
another challenge after the source claim and uses it to combine the source and
digit reconstruction identities. One degree-two selector sumcheck proves the
combined identity at a random selector point. The underlying public relation is
`digits = (1 - beta) * source + beta * maximum`, which simultaneously enforces
value reconstruction and `source + slack = maximum`; a false source or digit
identity can cancel only at the post-claim random mixing challenge. The combined
terminal evaluation is one additional opening of the same transition commitment.
The complete argument therefore uses four openings. Its executable n=10 fixture
is 25,985 bytes, of which 21,775 bytes are the Dory proof; changing a digit to
16 or changing it to another in-range value that breaks reconstruction prevents
the prover from preserving the claim. The canonical parser rejects incompatible
geometry, malformed lengths, and trailing bytes. The n=33 grammar projects to
78,529 bytes, including the 70,639-byte Dory payload.

Across the initialization transition and three banks, arithmetic needs 48
openings and the range checkpoints need sixteen. Adding nine matrix and 31 wiring
openings gives a 104-claim compressed subtotal. The composed transition verifier
requires its arithmetic and range halves to use the same packed commitment. The
shared proof grammar accepts the exact production topology of three matrix
proofs, four arithmetic/range transition pairs, and one wiring proof. A trusted
BLS fixed-model identity binds the existing `ModelPcsIdentity`, setup identity,
base-input commitment, and ordered weight-bank commitments. Each matrix weight
commitment must match it exactly. The shared transcript derives eleven equality
points after absorbing that identity and every component commitment and digest.

The feature-gated `bls-model-commitment` command is the offline ceremony bridge
for that identity. It takes the bank, a separately reviewed manifest, and a
separately reviewed `ModelPcsIdentity`; streams and authenticates every model
byte; derives the ordered BLS commitments; and emits a deterministic JSON record
with the manifest, identities, canonical compressed commitments, and a
domain-separated record digest. The deterministic setup's maximum variable
count must equal the padded geometry, so the production record uses `33`. The
command creates a requested output file only after authentication succeeds and
will not overwrite an existing file:

```text
cargo run -p cmfd-consensus --features dory-bls12-381-prototype -- bls-model-commitment --bank MODEL.bank --manifest MANIFEST.json --model-identity MODEL-PCS-IDENTITY.json --padded-variables 33 --output BLS-MODEL-COMMITMENT.json
```

Independent operators must reproduce the same record digest from the same three
inputs before it can be proposed for network pinning. Producing a matching
record neither replaces external review of the prior `ModelPcsIdentity`
ceremony nor activates production consensus.

One equality links the fixed base input to the virtual transition input, another
links that transition's activation to the wiring initial table, and three per
bank link matrix activation to wiring input, matrix accumulator to transition
input, and transition activation to wiring output. Opening both independently
committed representations adds twenty-two claims. The final-output bridge opens
the last transition activation and final wiring output at one fresh
BLS12-381 point, adding two claims and bringing the bounded aggregate to the
unchanged cap of 128. One shared Dory payload authenticates every ordered base,
equality, and bridge claim. Its complete n=33 frame projects to 133,409 bytes.
Tests reject changed model identities, fixed
commitments, equality values, and substituted, reordered, or omitted components.

The companion BLAKE3 bridge AIR now consumes the exact same eight byte columns
used by each narrow-tree compression row and accumulates their multilinear basis
weights at the Dory-derived point. It represents the BLS12-381 scalar with eight
32-bit limbs. Eight-nibble range decompositions, a bounded 12-bit quotient, and
bounded signed carry digits make each modular-reduction limb an exact integer
identity whose absolute value remains below the Goldilocks modulus. The verifier
therefore does not assume that Goldilocks and BLS12-381 evaluations can be
compared directly. A real cross-proof fixture obtains the point and evaluation
from the Dory verifier, proves the matching activation bytes and BLAKE3 digest,
and rejects byte substitution, point, challenge, digest, transcript-binding,
codec, and replay changes.

This correctness checkpoint does not yet fit the block proof budget. At the
smallest supported 32-byte activation, its 256-row trace has width 393 and
release runs produced 222,256- to 222,384-byte native frames. A canonical
best-zlib outer frame now caps decompression, binds the declared native length,
retains the inner proof identity, rejects trailing data, and requires
byte-identical recompression. The resulting wire frames measured 156,500 to
156,650 bytes under a 157,000-byte regression ceiling. Combining those measured
checkpoints with the current 133,409-byte production Dory projection and the
18-byte two-proof envelope gives 289,927 to 290,077 bytes, which remains 27,980
to 28,130 bytes above the 261,947-byte V3 structured payload allowance.

The parameter boundary is executable as well. With 18 query-grinding bits, the
production bridge requires at least 32, 28, 25, and 23 queries at log blowups 7,
8, 9, and 10. Keeping one query above each calculated minimum produces
compressed frames of 156,650, 145,632, 134,932, and 129,722 bytes. The last is
still 1,202 bytes over budget after composition, while its LDE is eight times
the configured size and the tiny-fixture prover slows from 394 to 2,538 ms.
At production shape, that `2^30`-row LDE contains 3,375,844,294,656 raw main
bytes (3,144 GiB) plus 721,554,505,728 raw preprocessed bytes (672 GiB) before
Merkle data or scratch space, and it has no pinned production preprocessed key.
Keeping log blowup 7 but dropping to 27 or 24 queries would require 35 or 45
grinding bits for 128 proven bits. This cross-shape calculation is not a
production-size measurement, but it rules out both direct composition and
operationally prohibitive grinding as completion. A narrower non-native range
argument or another sound aggregation/recursion strategy remains the next
proof-size gate.

A separate 56-point release-mode sweep held log blowup seven and the
128-proven-bit query margin fixed while varying FRI terminal lengths zero
through seven and maximum fold arities one through seven. Every tiny-fixture
proof verified under its exact configuration. The best canonical compressed
bridge was 154,606 bytes at terminal length six and maximum fold arity two. It
would produce a 288,033-byte candidate with the 133,409-byte Dory projection and
18-byte envelope, still 26,086 bytes over the cap. FRI folding geometry is
therefore a measured rejection rather than the missing size optimization.

The next bounded design eliminates that FRI frame. The narrow BLAKE3 execution
becomes a BLS/Dory sumcheck with 289 BLS-native main columns, where the
evaluation accumulator is one scalar rather than three Goldilocks limbs. It
exposes 746 local/next main and preprocessing terminal evaluations;
authenticating only one preprocessing evaluation would leave the shifted next
row unbound. A separate row-indexed LogUp permutation is projected to expose
580 more terminal evaluations and binds every committed next row to the
following local row; omitting that argument would let a prover choose unrelated
rows. Transcript-random selector batching reduces execution to one Dory opening
claim. Adjacency requires two claims because the source is committed before the
lookup challenge and the inverse is committed afterward. Together with the
current 128 claims, the design therefore requires 131 claims under a proposed
future bounded 256-claim parser.
Conservative wire accounting gives
36,020 bytes for execution and 21,748 bytes for adjacency, projecting the full
V3 payload at 191,185 bytes with 70,762 bytes of headroom. The current parser
remains capped at 128. These values are an executable layout projection, not a
proof-size measurement or an activation result.

A test-only canonical translator now converts all 1,305 existing BLAKE3 AIR
equations to centered integer expressions and evaluates them over BLS12-381.
An honest nonconstant 32-byte trace at a nonzero point satisfies every equation
on all 256 rows; a changed trace cell and a changed public point are both
rejected. The largest centered constant is exactly `2^33`. The three-limb
evaluation relation is now replaced in a test-only native layout: nine old
equations are removed, 1,296 translated equations remain, and three BLS-scalar
accumulator equations produce a 1,299-constraint, 289-column trace. The honest
trace reaches the Dory-authenticated raw-byte evaluation, while accumulator,
hashed-byte, Dory-point, and final-evaluation mutations fail. It is not yet
wired into a production out-of-core prover; adjacency soundness, a complete
n=33 run, independent review, and audit also remain.

The first dense execution sumcheck now combines all 1,299 native constraints
with a Fiat-Shamir challenge. The 256-row fixture verifies in eight degree-17
rounds with 18 evaluations per round, exposes all 746 local/next terminal
evaluations, and rejects round-message and terminal-value substitutions. A
transcript-random selector batches those values into packed Dory openings after
the commitments, sumcheck transcript, and terminal vector are fixed. The
bounded setup uses four 16-variable commitments and authenticates all values
with one four-claim Dory proof: three commitments contain main terminals and a
fourth contains preprocessing terminals. Changing that proof is rejected. The
projected production layout places those groups in separate 1,024-slot halves
of one 31-variable packed commitment and uses one execution opening claim, but
its out-of-core construction is not implemented or measured. Selector batching
adds at most degree-11 error over the BLS12-381 scalar field at production
geometry, before the complete union bound. This checkpoint remains
non-admissible.

The bounded adjacency argument now commits the local/next source before
compressing complete main rows, commits its two inverse tables after the lookup
challenge, and forms the two cyclic indexed multisets
`(r, next[r])` and `((r - 1) mod N, local[r])`. The row index prevents a prover
from hiding reordering behind ordinary multiset equality, and the modular label
also binds the final-row-to-first-row wrap. Two inverse tables enforce the
LogUp denominator equations through an equality-weighted local relation; the
sum of their difference enforces the global permutation identity. Its 256-row
sumcheck uses eight degree-three rounds with four evaluations per round and
exposes the projected 580 terminals. A changed cell, reordered or duplicated
row, changed wrap boundary, round substitution, or terminal substitution is
rejected. A 16-row fixture retains all 289 main columns, packs its 578 source
tables into one 16-variable Dory commitment, and packs both inverse tables into
a second. Two transcript-random selector openings authenticate all 580 terminal
evaluations; source-commitment, terminal, and opening-proof mutations fail.
Production reuses the 31-variable execution source commitment with its half
selector fixed and randomizes the remaining 10 selector variables; one separate
31-variable commitment holds the inverse tables. The out-of-core path and the complete
row-compression and lookup-challenge soundness bound remain to be implemented
and reviewed.

The composed 256-row fixture passes the first end-to-end source-identity gate.
Execution uses four bounded commitments: three main groups and one preprocessing
group. Adjacency reuses the exact three main commitments at its independent
sumcheck point and adds only the inverse commitment. One eight-claim Dory
aggregate authenticates all of those openings. Three optimized repeats proved
in 8.298--8.621 seconds (8.476-second median), verified in 0.759--0.773 seconds
(0.762-second median), and emitted the same 34,015-byte aggregate opening.
Shared-source substitution, adjacency-terminal
substitution, inverse-commitment substitution, and opening-proof mutation are
all rejected. At production geometry the four bounded source groups project to
one 31-variable source commitment with main and preprocessing tables in separate
halves. These measurements cover the 256-row, 16-variable fixture only. That
unification, its out-of-core prover, and peak-memory measurement are not
implemented.

The executable production-geometry algebraic report now closes the accounting
list, though not its review gate. Execution contributes constraint-mixing,
local-equality, degree-17 sumcheck, and 11-selector batching terms. Adjacency
contributes the conservative `2^20 * 289 = 303,038,464` row-compression term,
the `2 * 2^20 - 1 = 2,097,151` lookup-alpha rational-identity term, local and
global mixing, its equality point, degree-three sumcheck, and two 10-selector
batches. The custom numerator is 305,137,386. Unioning it with the existing
19,781,388,263 shared-proof numerator gives 20,086,525,649 over at least
`2^254` nonzero BLS12-381 scalar challenges, retaining a 219-bit algebraic floor
and 91 bits of grinding headroom above the 128-bit requirement. Dory knowledge
soundness, Fiat-Shamir security, implementation correctness, and external audit
remain separate unreviewed assumptions.

The deterministic setup now admits the required n=33 square-root generator
geometry separately from the n=16 materialized-polynomial cap. The aggregate
prover no longer retains a duplicate coefficient vector or builds a full
combined polynomial for the final Dory opening: it streams authenticated
coefficients into `L^T M` and feeds the unchanged Dory state machine. Repeated
claims backed by one authenticated artifact combine their opening scales first,
so that final vector-matrix product reads each physical source once. The
distinct-point sumcheck recognizes cloned artifact handles as the same source,
folds each repeated polynomial only once, and generates equality weights without
full equality tables. Its pre-change 17,695-byte fixture remains pinned
at BLAKE3 digest
`6aa99fd095e70180b6b2fdd94dc96fc420f99eb529ec03ad5dfa978731d9cfac`.
An explicit scratch API now writes every post-challenge unique-table fold to a
self-authenticating, lineage-bound artifact. It uses a two-decoded-scalar fold
working set plus a bounded 1 MiB encoded buffer per open reader or writer (2 MiB
for simultaneous fold input and output),
rejects corruption, truncation, non-canonical fields, and trailing bytes, removes
partial or completed files only while it still owns them, and aborts without a
dense fallback. A row-source constructor now computes ordinary row and tier-two
commitments while writing the canonical explicit coefficient prefix to the same
self-authenticating storage boundary. The artifact header binds both its logical
power-of-two length and explicit length, making the omitted suffix canonical
zeros; every later fold preserves that implicit tail instead of writing padded
zeros. The scratch-enabled shared prover uses it for every matrix, fixed-base,
transition, LogUp, and wiring commitment. Matrix terminal evaluation and wiring
commitment/evaluations read signed witness slices directly with bounded working
memory; the transition commitment derives all 110 regular and radix-16 lanes
directly from the witness. Its arithmetic sumcheck reads raw rows for the first
round, keeps equality-selector weights implicit, and authenticates later folds
in scratch artifacts with 12 live lanes inside a 16-scalar row. The standalone
aggregate and complete shared-layout fixture produce exactly the same proof
through that path. The shared scratch path passes that authenticated transition
source directly into LogUp instead of writing the same 110-lane table again.
LogUp still checks its terminal and reconstruction evaluations against the
shared commitment, and tests reject a same-shape artifact with different
coefficients. It streams the inverse commitment and folds each cell-variable
sumcheck round with linear work. The first four lineages store each regular
selector as one scalar and each range cell as the original radix-16 digits in
one-, two-, four-, and eight-byte codes. They represent two, four, eight, and
sixteen digits respectively. Every format binds the Fiat-Shamir context,
reconstruction challenges, dimensions, parent digest, and complete payload.
Generation five reconstructs the exact two scalar lanes and returns to the
ordinary fold format. LogUp retains only the 128 selector-boundary
values at production geometry. Its reconstruction evaluations also stream from
the witness. Dense and scratch fixtures match exactly at both the minimum layout
and an extra padded variable. The complete n=33 run has not measured proving
latency, verification latency, peak memory, scratch use, or final proof size;
CPU fold latency and retained source storage therefore remain activation gates.
Executing the final model commitment ceremony, independent review of the
transcript and soundness accounting, and external audit also remain activation
requirements.

Release-mode scaling makes the remaining LogUp problem concrete. On a Ryzen 9
9950X3D with 64 GiB RAM under Windows, the exact scratch prover, aggregate
opening, and unchanged verifier produced these complete results. "Recompute"
is the rejected `O(N log N)` implementation; "linear" is the current
lineage-authenticated scalar/compact hybrid with bounded 1 MiB artifact reads
and writes. Row commitments are computed in deterministic
parallel batches behind a bounded 256 MiB coefficient window; source reads,
artifact writes, and target-group accumulation remain in canonical row order.
The verified model-bank writer now uses the same bounded row-batch boundary:
arbitrary authenticated input chunks are reassembled into canonical rows,
committed in parallel, and published only after the model receipt verifies.
Three n=19 release A/B repeats measured 814--826 ms for the former serial
writer and 377--391 ms for the parallel writer. Their 822 and 385 ms medians
give a 53.2% reduction, with identical artifact digest, row commitments,
tier-two commitment, opening claims, and proof bytes.
The authenticated indexed formats support either a literal-scalar prefix or
signed/unsigned 32- or 64-bit words followed by four- or eight-bit dictionary
codes. Transition artifacts store twelve consensus-bounded lanes as 32-bit words
and pack the remaining 98 radix-16 lanes two authenticated digits per byte. The
inverse stores zero and the sixteen possible
`1 / (alpha - digit)` values once, rejects a zero denominator before publishing
the commitment, and maps the transition's authenticated digit codes without a
second coefficient file. The Dory G1/G2 MSM and
elementwise vector routines also use ordered CPU-parallel maps and normalize to
the same group elements and proof bytes.

| Cell variables | Cells | Packed variables | Recompute prover | Compact prover | Prepared scratch | Aggregate opening | Verify | Proof | Scratch after proof |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 256 | 15 | 4.696 s | 1.925 s | 50,940 B | 1.803 s | 0.681 s | 38,929 B | 0 B |
| 10 | 1,024 | 17 | 15.160 s | 4.097 s | 199,932 B | 3.513 s | 1.254 s | 43,329 B | 0 B |
| 12 | 4,096 | 19 | 53.948 s | 9.431 s | 795,900 B | 7.064 s | 2.377 s | 47,729 B | 0 B |

The current implementation derives every child file from the Fiat-Shamir
challenge, authenticates its complete header and scalar payload, binds it to the
previous generation's digest, and deletes the parent as ownership leaves scope.
The buffered implementation produces byte-identical artifact files and digests
across the buffer boundary. Buffering alone reduced the prior direct-I/O n=19
measurement from 48.385 to 42.699 seconds proving and from 19.315 to 10.618
seconds opening. Bounded parallel row commitments reduced proving to 9.952
seconds, and parallel Dory MSM/vector routines reduced opening from 10.504 to
7.244 seconds. Compact transition artifacts, mapped inverse views, and four
compressed lineage generations measured 9.480 seconds proving in the
release/regeneration run. Releasing the source reduced scratch from 795,900
bytes to 644 bytes; exact regeneration took 2.267 seconds and restored 795,900
bytes before the 7.043-second opening. Verification took 2.381 seconds, proof
bytes remained 47,729, and final scratch was zero.
Dense and scratch proofs and opening claims match exactly at the minimum
production selector width and with an extra padded selector bit. The largest
simultaneous LogUp lineage overlap at n=19 is now exactly 1,581,400 bytes.
Aggregate preparation now derives the complete sumcheck, combined row
commitments, and `L^T M` vector before final Dory proving. The shared path then
consumes its deferred openings, releases their authenticated coefficient
artifacts, and completes the unchanged Dory transcript without borrowing those
sources. A direct test deletes the source at that boundary and obtains the same
proof bytes; the three standalone benchmark runs leave zero scratch bytes after
proof completion. These are component measurements, not production results.

A linear extrapolation from n=19 to n=33 gives about 1.80 CPU days for the
LogUp prover, 10.32 hours for each regenerated source (1.72 days for four
sequential sources), and 1.34 days for the aggregate opening. The four compressed
production lineages are exactly 16,173,236,396, 9,730,785,452,
6,509,559,980, and 4,898,947,244 bytes. Their maximum adjacent overlap remains
the first two at 25,904,021,848 bytes, or about 24.125 GiB. Delaying the first
ordinary scalar artifact until generation five removes the former 64.06 GiB
transition overlap.
Exact production geometry stores the transition's 805,306,368 regular values
in authenticated per-selector 1-, 2-, 3-, and 4-byte words totaling 36 bytes
per cell, plus 6,576,668,672 packed digit codes, in 5,704,254,080 bytes, about
5.313 GiB including framing.
The mapped inverse reuses those authenticated digits and adds no coefficient
file. One retained transition/inverse pair is about 5.313 GiB and four sources
are exactly 22,817,016,320 bytes, about 21.25 GiB. The shared prover now retains
each compact source's exact
format, dictionary, and BLAKE3 digest, releases the completed source before the
next pair builds its lineage, and regenerates all four immediately before shared
openings. Regeneration writes only the canonical word/code artifact and reuses
the original Dory commitment and row commitments; a changed witness or any
identity mismatch aborts. The construction-phase source-plus-lineage peak is
31,608,275,928 bytes, about 29.44 GiB, and is now larger than the four-source
regeneration boundary. The transition/range storage peak is therefore
31,608,275,928 bytes, down from 77,980,502,840 bytes or 72.62 GiB. Executable
projection
functions pin all source, lineage, and peak sizes. Exact fixtures preserve the
complete proof bytes, reject a one-byte regenerated-source substitution, and
leave zero scratch files. The distinct-point aggregate now recognizes each
compact transition and mapped-inverse pair that shares one authenticated source.
For its first eight folds it scans the authenticated compact source and exposes
two role-bound logical views: regular transition lanes reconstruct as scalars and
zero inverse lanes, while every range code reconstructs both the transition digit
and mapped inverse. Each view lineage binds the transcript context, source and
mapping identities, both original parent lineages, role, and every folding
challenge. At fold nine the two views materialize as ordinary authenticated scalar
lineages. Corrupting the shared source aborts proving, and dense, ordinary scratch,
and compressed scratch paths produce exactly the same proof bytes.

Two n=19 release runs measured 9.561 and 9.729 seconds for component proving,
2.294 and 2.314 seconds for authenticated source regeneration, 7.282 and 7.220
seconds for aggregate opening, and 2.446 and 2.415 seconds for verification. Both
retained the 47,729-byte proof, ended with zero scratch, and measured the same
2,377,688-byte opening peak with a 1 ms observer, down from 18,819,084 bytes by
7.91 times. A complete three-bank n=19 shared-layout benchmark then measured an
84,717-byte proof, 92.212 seconds proving, 7.045 seconds verification, and zero
retained scratch. Its 6,866,772-byte observed peak exactly matched the executable
aggregate-lifecycle projection, down from the 10,963,892-byte pre-compression
baseline by 1.60 times while preserving proof bytes. Accumulators retain
canonical signed words. Bounded activation and wiring sources retain the first
Dory row as signed words and encode every remaining value as one authenticated
byte selecting the fixed signed dictionary. For the first eight aggregate challenges, role-bound source
views recompute their folds directly from that authenticated source and bind the
source digest, original polynomial lineage, mapped-inverse identity where applicable,
Fiat-Shamir context, and every challenge; generation nine
returns to ordinary authenticated scalar artifacts. Exact differential tests
preserve commitments, claims, and aggregate proof bytes, while altered lineage
digests and source corruption abort. Model weights use the stricter production
bound of `[-125, 125]`: the first Dory row remains canonical signed words and every
remaining weight is one authenticated byte selecting the fixed dictionary
`0, -1..-125, 1..125`. The model-bank streaming writer produces this format
directly, so it never creates the former 32-byte-per-weight scalar artifact.

The complete executable n=33 aggregate-stage projection now includes every matrix,
transition, multiplicity, wiring, and fixed-base source plus the entire ordered
fold-artifact lifecycle. Authenticated dictionary coding reduces the three matrix
sources from 9,666,454,296 to 8,259,944,736 bytes, transition sources from
29,470,231,008 to 17,157,327,360 bytes, and wiring from 3,758,096,536 to
470,687,712 bytes. Retained sources total 25,904,739,732 bytes (about 24.1
GiB), the fold peak remains 3,297,676,512 bytes (about 3.1 GiB), and their
combined peak is 29,202,416,244 bytes (about 27.2 GiB). This is a 15.03-times
reduction from the prior complete 438,943,885,320-byte projection (about 408.8
GiB), a 3.80-times reduction from the earlier 110,935,310,868-byte projection,
and a 7.66% reduction from the immediately preceding 31,624,626,692-byte
projection. It is still a code-pinned rejection estimate, not a production
measurement. Further reduction or distribution and a complete unchanged n=33
run remain mandatory. A fresh complete n=19 release run preserved the
84,717-byte proof, measured 100.568 seconds proving and 7.299 seconds
verification, observed a 48,669,452-byte full-prover scratch peak
against a 1,546,068-byte aggregate-stage projection, and retained zero scratch
after completion.

Dory works over the pairing scalar field, while the packed AIR uses the cubic
Goldilocks extension. A direct field embedding is impossible because the
characteristics differ. Cross-field tests do show that the canonical
bounded-integer witness makes all 121 local transition constraints vanish in
the cubic Goldilocks field, the BN254 reference scalar field, and the actual
BLS12-381 scalar field across signed boundary cases, while altered reductions
and digits fail with the same constraint pattern in all three. The selected
route is therefore native scalar-field re-arithmetization. The distinct-point,
matrix, full local-transition, and successor-wiring transcripts are now ported.
The scalar LogUp membership and source/slack reconstruction identities and the
seven-constraint arithmetic sumcheck are connected through the same packed
transition commitment. The shared layout also authenticates the eleven
fixed-model and cross-component equalities described above. The individual tables
accept the common n=33 layout and the executable algebraic report covers this
topology, but streaming that shared geometry, independent soundness review,
production latency and peak-memory measurement, and external audit remain
mandatory activation gates.

For the complete tiny structured fixture, the enforced component bounds give a
154,252-byte maximum for the split WHIR proof. The canonical one-block BLAKE3
proof is bounded at 87,556 bytes, and the remaining aggregate components are
exactly 16,804 bytes. The aggregate maximum is therefore 258,612 bytes.
The reserved `BlockProof::V3Candidate` frame keeps the same 177-byte public
payload, adds a canonical four-byte aggregate length, and remains under the
same 16-byte outer header. It therefore gives the tiny fixture a 258,809-byte
full-wire maximum, leaving 3,335 bytes below the 256 KiB cap. The executable
codec admits at most 261,947 structured-proof bytes, rejects zero length and
oversize declarations before allocation, and binds the proof type, public
fields, aggregate length, and exact aggregate bytes into the block ID. This
bound does not use the smaller path dictionaries observed in individual prover
runs and applies only to the tiny research fixture, not the production shape.

Native proof v2, structured aggregate v3, split v3, and the revised suite
identity are a hard cutover for research artifacts. Older explicit proofs,
structured proofs, model bundles, and source pointers must be regenerated. This
does not fork the current Devnet block format. Proof tag 3 is reserved for the
candidate envelope, but `PowParameters` exposes no V3 selection and
`ConsensusPowVerifier` rejects it as the wrong proof type. Activation still
requires a pinned structured-proof parser, final model and verifier parameters,
resource-bounded verification, network fingerprint changes, and explicit
consensus selection rather than reusing the compact reference tag.

External block admission now separates proof verification from mutable node
state. The verifier issues a nonserializable process-local capability bound to
the exact verifier parameters, block challenge, proof type, public fields, and
proof bytes. Outbound synchronization, inbound `SubmitBlock`, and the shared
loopback block RPC verify before acquiring the node mutex, then consume that
capability while rerunning every parent, height, target, timestamp,
transaction, UTXO, coinbase, fork-choice, and persistence check. Admission is
serialized to one active proof with at most eight waiting callers and a
five-second queue timeout; saturation is retryable, verifier panics reject only
the candidate, and active/queued counts are observable in node status. Devnet
keeps bounded in-process admission as its default. Operators can now select a
hash-pinned short-lived verifier process for external blocks. Its canonical
request and response bind the exact verifier parameters, challenge, proof
type, public fields, and proof bytes. Windows Job Objects and Unix process
groups terminate the process tree on timeout, crash, malformed or oversized
output, while an explicit Windows job-memory or Unix address-space limit bounds
the worker. Hash mismatch and response substitution fail closed. This is crash
and resource containment rather than an OS sandbox, supports only the active
V2 reference verifier, and does not move side-branch replay out of process.
Production therefore still requires final V3 parser/verifier integration,
production-shape resource limits and load tests, protected executable
deployment, and independent review.

The feature-gated BLS/Dory candidate now has a narrower, explicitly
non-consensus verifier boundary. It validates an authenticated model-commitment
record at the exact n=33 production geometry, recomputes the block challenge
and work digest, enforces the target, derives each transition bank's masks from
its global layer offset, and verifies the canonical shared-Dory plus native
BLAKE3 envelope through one exact 128-plus-6 opening aggregate. The materialized
research constructor derives the final activation only from the last wiring
output, rejects noncanonical centered bytes and losing work before expensive
proving, constructs the pending-output bridge, composes both proof halves, and
self-verifies the unchanged envelope before returning it. This closes the
implemented same-table binding path without creating a chain-admission
capability. V3 remains unselectable by `PowParameters`: the runtime cannot yet
stream an authenticated production execution witness into this constructor,
the final model record is not pinned, and no unchanged exact n=33 candidate has
completed twice with proof size, proving and verification time, peak memory,
peak scratch, and cleanup recorded. Independent review and external audit also
remain mandatory.

The component proof constructors receive the fixed or trace commitment aliases
before any component transcript samples challenges, and
`StructuredWhirPcsVerifier` authenticates both scoped claim sets. This closes
commitment selection and bank-order substitution in the research boundary; it
does not make the commitment/proof adapter production-capable. The production
base table has 19 variables and each weight bank has 31. Source staging, exact
initial-codeword construction, typed initial trees, and V2 oracle preparation
now admit both geometries; the typed role join binds each prepared artifact set
to the corresponding structured alias, model identity, and role. The explicit
proof adapter still admits at most 16 variables per table. The separate
production candidate defines the n=31 configuration and parser grammar but
fails its unchanged network byte gate, and the production-geometry extension
transform is not executable through the current `2^20`-row reference encoder.
No complete 31-variable preparation or proof run has been benchmarked. The
upstream backend is an unaudited academic prototype. Proof-size redesign,
review, benchmarks, fuzzing, a complete soundness report, and independent
audits remain mandatory before any production selection.

The PCS adapter must stream production model and trace data. Expanding every
model byte into an in-memory 32-byte field object, retaining duplicate encoded
matrices, or padding smaller trace tables to the 6 GiB model shape is an
automatic rejection for the 16 GiB target.

## 7. Soundness accounting

For one matrix bank in the original cubic-Goldilocks path, the sumcheck error
is bounded by

```text
(2*log2(D) + 3*log2(L)) / |Fp^3|.
```

At `D=4096` and `L=128`, the numerator is 45. Native BLS re-arithmetization has
the same degree numerator over `Fr*`. The BLS report also counts the
26-variable random point that reduces the complete matrix relation. The
original direct transition baseline uses a degree-17 sumcheck over 26 variables
(`7 layer + 7 row + 12 column`), giving numerator 442, while mixing 121
constraints contributes at most 120 more. The split BLS arithmetic checkpoint
lowers its bank sumcheck contribution to `3 * 26 = 78` and mixes seven
constraints. Degree-four LogUp rounds, the randomly combined degree-two
selector sumcheck, lookup and reconstruction-mixing challenges, random
cell/spec evaluation, slack mixing, wiring identities, equality links, and
distinct-point aggregation are all included in the executable BLS algebraic
report. Dory knowledge soundness, hash collision assumptions, the Fiat-Shamir
reduction, and proof-attempt grinding remain separate computational and
operational obligations.

The successor argument contributes numerator 135 for the production shape:
three 26-variable within-bank identities, two 19-variable bank-boundary
identities, and one 19-variable initialization identity. This is accounted
before PCS binding error and Fiat-Shamir grinding.

For the exact production topology, the machine-derived conservative numerator
is `19,781,388,263`. The dominant contribution is the LogUp lookup challenge:
for each transition, the report grants a nonidentical rational multiset identity
one root per active range value plus all sixteen table values. The initialization
has `98 * 2^19` active values and each of three banks has `98 * 2^26`. All
remaining matrix, transition, reconstruction, wiring, link, final-output, and
aggregate terms sum to 1,959. BLS12-381 `Fr` has a 255-bit modulus, so
`|Fr|-1 >= 2^254`; because
the total numerator is below `2^35`, the algebraic false-accept probability is
strictly below `2^-219`. This leaves 91 bits of simple proof-attempt union-bound
grinding headroom before reaching the required 128-bit algebraic floor.

That 219-bit figure is not a claim that the complete system has 219-bit security.
The implementation targets 128-bit computational security and remains
fail-closed because Dory knowledge soundness, the BLAKE3 Fiat-Shamir transform,
and the codec/implementation have not been independently reviewed or externally
audited. The report's readiness predicate stays false until those flags are
explicitly changed after review.

## 8. Miner shortcut boundary

The proof prevents acceptance of a false relation; it does not force a miner
to use the reference kernel, CUDA, tensor cores, a GPU, or physical VRAM.
Equivalent arithmetic, compression, tiling, and specialized hardware remain
valid. The seedless model, exact ranges, nonlinear transitions, and complete
layer binding are intended to remove known relation shortcuts, but the claim
must remain "no known bypass after review and testing," never "cheating is
mathematically impossible."

## 9. Remaining activation work

Three sanitizer-ready `cargo-fuzz` targets now exercise the outer structured
aggregate decoder, the nested BLS shared-layout decoder, and the V3 candidate
envelope. The shared-layout target uses a valid fixed topology and a format
dictionary so mutations reach matrix, transition, LogUp, wiring, and
field-element decoding instead of stopping at the outer header. Bounded Windows
MSVC smoke campaigns completed one million executions for each of the first two
targets without a crash, panic, timeout, or sanitizer finding. A Linux
AddressSanitizer smoke campaign completed 10,000 executions of the V3 envelope
target without a crash, panic, timeout, or sanitizer finding. These are
reproducible starting dictionaries and harnesses, not an exhaustive fuzzing
claim or a substitute for sustained independent campaigns.

Before a production proof tag can exist:

1. harden and independently review the aggregate transparent PCS backend,
   canonical parameters, parser, and explicit-point transcript;
2. execute, independently reproduce, benchmark, and audit the complete
   production model path from the published source bundle through the exact
   initial codewords, typed demand trees, and typed role joins, retaining the
   V2 identities, reproducing the offline fixed-model commitment record, and
   verifying every structured commitment alias against the pinned
   `ModelPcsIdentity`;
3. run the exact BLAKE3 tree argument at the complete production shape and
   demonstrate that the full aggregate, not only the hash component, remains
   below its total payload cap;
4. sustain sanitizer fuzzing of the bounded aggregate parsers, preserve every
   finding as a deterministic regression, and add a bounded, panic-contained
   network verifier queue when the production frame is integrated;
5. demonstrate production-size streaming proving within the memory, proof-size,
   proving-time, and verification-time gates;
6. publish independent prover/verifier implementations and canonical vectors;
7. complete cryptanalysis, fuzzing, an adversarial testnet, and two external
   audits.
