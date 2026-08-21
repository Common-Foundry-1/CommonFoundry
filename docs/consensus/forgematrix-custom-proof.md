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
abort before that publication barrier. The feature-gated WHIR sink now writes
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

The implemented successor layout attacks width rather than soundness. Of the
110 transition oracles, 12 carry the actual algebraic values and 98 are paired
base-16 digits for eight value/slack range checks. Initialization retains 11
core columns because its input is fixed; the three banks retain 12 each. The
ordered production core is therefore 47 semantic columns padded to 64 slots.
Range witnesses are transposed row-wise: each original cell owns 64 auxiliary
rows, the first 49 enumerate digit counts `[7,7,7,7,7,5,2,7]`, and the final 15
are canonical zero padding. Each active row carries only digit, slack digit,
value accumulator, and slack accumulator. Its lookup ID, source oracle, bound,
radix, and first/last selectors are verifier-fixed. The final accumulator row
can consequently be linked to the corresponding core source through LogUp,
while both digits query a fixed 16-value table.

This makes the initialization auxiliary table `n=25` and each bank auxiliary
table `n=32`, exactly at rather than above Goldilocks two-adicity. The code now
generates every canonical row, rejects out-of-range sources and rows, pins the
47-column order, and commits the complete structural plan under digest
`6c7ccc9e63cae28907ae173372ddf33a3526f2ea2cc46b514510e4b330082769`.
It is a layout and witness checkpoint, not yet a production-sized batch-
STARK/LogUp verifier or evidence that the complete aggregate fits the network
frame.

The first batch-STARK reduction for this layout is now executable on an
eight-cell, 512-row fixture. Each of the eight range specifications gets a
separate local LogUp bus binding `(lookup ID, source, maximum - source)` from
the core row to `(lookup ID, value accumulator, slack accumulator)` on the
final digit row. Two additional buses bind value and slack digits separately
to the verifier-fixed `0..15` table. Separate buses avoid the degree-ten
quotient caused by multiplying nine denominators on one bus: the pinned AIR
has maximum degree three, 52 total constraints, one quotient split, and 33
base-field lookup auxiliary openings at each local and next evaluation.

With the configured 33 FRI queries, the library's executable estimator reports
128 list-decoding bits; 32 is the first query count reaching that target. A
separate root count covers same-bus and cross-bus beta collisions, false
rational sums, and all denominators under the single shared `(alpha, beta)`
pair. Its 847,343 roots over the cubic Goldilocks extension give an error below
`2^-172`. Tests reject changed value/slack digits, accumulators, core sources,
padding, table multiplicities, lookup IDs, bounds, radices, active rows, table
values, and untrusted degree vectors. This remains test-only: the production
argument still needs the transition arithmetic AIR, production-sized
preprocessed-key construction, native canonical encoding, aggregate size and
latency measurements, and verifier integration.

For the complete tiny structured fixture, the enforced component bounds give a
154,252-byte maximum for the split WHIR proof. The canonical one-block BLAKE3
proof is bounded at 87,556 bytes, and the remaining aggregate components are
exactly 16,804 bytes. The aggregate maximum is therefore 258,612 bytes.
Retaining the current 193-byte V2 proof frame and adding a four-byte aggregate
length gives a 258,809-byte full-wire maximum, leaving 3,335 bytes below the
256 KiB cap. This bound does not use the smaller path dictionaries observed in
individual prover runs and applies only to the tiny research fixture, not the
production shape.

Native proof v2, structured aggregate v3, split v3, and the revised suite
identity are a hard cutover for research artifacts. Older explicit proofs,
structured proofs, model bundles, and source pointers must be regenerated. This
does not fork the current Devnet block format because succinct WHIR is not yet a
block-proof variant; activation requires a new proof tag rather than reusing
the compact reference tag.

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
2. execute, independently reproduce, benchmark, and audit the complete
   production model path from the published source bundle through the exact
   initial codewords, typed demand trees, and typed role joins, retaining the
   V2 identities and verifying every structured commitment alias against the
   pinned `ModelPcsIdentity`;
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
