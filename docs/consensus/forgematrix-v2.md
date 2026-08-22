# ForgeMatrix v2 recommended research specification

Status: **the production profile is a design target, not an activated consensus
algorithm**. A separate tiny v2 reference profile is connected to Devnet-0
block acceptance for local testing. The parameter set below is the recommended
16 GiB research profile; it remains hard-disabled and is not permission to
launch a public-value network.

ForgeMatrix v2 is intended to prove the committed matrix relation with a
transparent succinct argument. It proves neither that a particular GPU was
used nor that the model was physically resident in GPU VRAM.

## Fixed research profile

| Parameter | Value |
|---|---:|
| Batch, `B` | 128 |
| Dimension, `D` | 4096 |
| Layers, `L` | 384, organized as 3 banks of 128 |
| Weight encoding | one raw byte in `0..=250`, decoded as `byte - 125` |
| Activation encoding | one raw field representative in `0..=250`, decoded as `value - 125` |
| Dominant arithmetic | signed INT8 x INT8 GEMM with exact INT32 accumulation |
| Transition modulus, `P` | 134,217,689 (prime) |
| Output alphabet modulus | 251 |
| Proof base field | Goldilocks, `p = 2^64 - 2^32 + 1` |
| Transcript challenge space | at least 192 bits; a degree-4 Goldilocks extension is recommended |

The 384 weight matrices contain exactly `384 * 4096 * 4096 =
6,442,450,944` raw bytes (6 GiB). The base input table contains another
`128 * 4096 = 524,288` bytes. Each matrix and the base table are row-major.
Bytes `251..=255` are invalid; generation samples bytes by rejection rather
than reducing an eight-bit value modulo 251.

The three weight banks contain layers `0..127`, `128..255`, and `256..383`.
The grouping gives each bank power-of-two multilinear dimensions and has no
rule that permits a bank or layer to be omitted.

## Model artifact and its two commitments

The model is a published raw artifact, not a 32-byte seed expanded by consensus
code. Its ordered payload is the base input table followed by `W_0` through
`W_383`. The canonical model-bank format and manifest fix the model version,
`B`, `D`, `L`, byte encoding, order and length of every table, byte roots, PCS
parameter digest, and PCS commitment root. The enclosing consensus descriptor
separately fixes the network, algorithm/proof versions, and bank layout.

The current canonical file header is exactly 184 bytes in this order:

```text
8 bytes   ASCII magic "CMFDBNK2"
u32 LE    format version = 2
u32 LE    header length = 184
u32 LE    model version
u32 LE    dimension D
u32 LE    batch B
u32 LE    layer count L
u64 LE    base-input byte length
u64 LE    bytes per layer
u64 LE    total payload bytes
32 bytes  raw payload BLAKE3 root
32 bytes  layer-roots aggregate
32 bytes  PCS parameter digest
32 bytes  PCS commitment root
```

The payload immediately follows: base table, then layers `0..L-1`, with no
trailing bytes. The raw root is ordinary BLAKE3 over that exact payload. For
each layer, `layer_root_i = BLAKE3(layer_i)`, and
`layer_roots_aggregate = BLAKE3-derive-key("CMFD/FORGEMATRIX/V2/LAYER-ROOTS",
u32_le(L) || each u32_le(i) || layer_root_i)`. The manifest digest is
BLAKE3 derive-key with `"CMFD/FORGEMATRIX/V2/MANIFEST"` over the complete
canonical 184-byte header.

The manifest carries two distinct bindings:

1. A BLAKE3 byte root identifies the exact raw payload used for distribution
   and reproducible auditing. A separate domain-separated manifest digest
   binds that root to the canonical header and all other manifest fields.
2. A transparent polynomial-commitment-scheme (PCS) commitment binds the field
   polynomials opened by the block proof.

A one-time, independently verifiable link certificate must prove that every PCS
entry is the field encoding of the corresponding byte under the BLAKE3 root,
including the rejection of `251..=255`. Alternatively, every full node may
stream the complete artifact and deterministically recompute both bindings at
model activation; that expensive check must produce the same manifest hash.
A BLAKE3 root by itself is not a PCS commitment, and merely placing both values
in one manifest does not prove that they describe the same data.

The recommended PCS layout is one multilinear commitment for the base table,
indexed by 7 row bits and 12 column bits, and one commitment for each 128-layer
weight bank, indexed by 7 layer bits, 12 common-dimension bits, and 12 output-
column bits. The scheme must be transparent: no participant-generated trusted
setup or hidden toxic waste is allowed.

MLE point vectors use the least-significant, fastest-changing row-major axis
first. The base table uses `[column, row]`; a weight bank uses
`[column, common, layer]`; activation and witness banks use
`[column, row, layer]`. The final PCS suite must canonically encode and order
the base commitment followed by banks 0, 1, and 2, then domain-hash those four
encodings into `pcs_commitment_root`. The concrete suite ID and wire encoding
remain to be selected and frozen.

No short public generation seed may be included in the activated manifest.
This removes the specific consensus-sanctioned shortcut of regenerating each
layer from a tiny seed. It does not prove that the published bytes are
information-theoretically incompressible, so the generation ceremony, entropy
sources, resulting artifact, and structural analyses still require public
review.

## Block challenge and affine masks

The domain-separated v2 challenge binds, in canonical byte encoding, at least:

- chain identifier and proof-protocol identifier;
- algorithm version, model version, manifest hash, byte root, and PCS
  commitments;
- previous block hash and transaction Merkle root;
- height, timestamp, the chain-derived difficulty target, and nonce.

For the virtual input layer and every real layer `l` in `0..383`, derive one
constant coefficient, seven row-bit coefficients, and twelve column-bit
coefficients from a domain-separated BLAKE3 XOF keyed by the complete block
challenge and a canonical `u32` layer tag. The virtual layer tag is
`0xffffffff`; real layer tags are `0..383`. Consume the XOF byte stream in
order, accept candidates in `0..=250`, and reject `251..=255`. No `% 251`
reduction is permitted during coefficient sampling.

Writing `r_i` and `c_j` for the little-endian Boolean index bits, define the
ordinary integer mask

```text
M(l,r,c) = a_l + sum(i=0..6, br_l[i] * r_i)
               + sum(j=0..11, bc_l[j] * c_j)
```

Do not reduce `M` before adding it to the accumulator. It lies in `0..=5000`.
The same affine expression evaluates its multilinear extension at a verifier's
random row/column point, avoiding a committed per-cell mask table or a hash
inside every transition constraint. Coefficient derivation is outside the
large matrix circuit, but its transcript inputs and rejection-sampling rules
are consensus data and must be checked by the verifier.

## Base input and layer relation

The committed base table is not used directly. Treat it as a virtual layer:
decode its entry to `s = base_raw[r,c] - 125`, apply the virtual-layer affine
mask, and apply the same mod-251 cubic permutation below. Its output is
`X_0[r,c]`.

For each real layer, decode `W_l[k,c] = weight_raw - 125` and compute

```text
s_l[r,c] = sum(k = 0..4095) X_l[r,k] * W_l[k,c]
```

This is an exact signed-integer dot product. Floating point, TF32, stochastic
rounding, saturation, and wraparound are not part of the relation.

For either the virtual layer or a real layer, first encode the signed `z` into
the prime transition field `P = 134,217,689`, then apply its cubic permutation
and reduce only the final field representative to the byte alphabet:

```text
z = s + M(l,r,c)
e = z                     when z >= 0
e = P + z                 when z < 0
e^2   = P*q2 + r2         with 0 <= e,r2 < P
r2*e  = P*q3 + h          with 0 <= h < P
h     = 251*t + v         with 0 <= v <= 250
next_raw = v
next_signed = v - 125
```

For a real layer, `next_signed` is `X_(l+1)[r,c]`; for virtual layer `-1`, it
is `X_0[r,c]`. `P` is prime and `P mod 3 = 2`, so `gcd(3, P-1) = 1` and cubing
is a permutation of the transition field. Reducing the dot product directly
modulo 251 is not equivalent to this function.

### Exact integer bounds

With `D = 4096` and both operands in `[-125,125]`, every real-layer dot product
obeys

```text
-64,000,000 <= s <= 64,000,000
-64,000,000 <= z <= 64,005,000
0 <= e,r2,h < 134,217,689
0 <= q2,q3 <= 134,217,687
0 <= t <= 534,731
0 <= v <= 250
-125 <= next_signed <= 125
```

For the virtual layer, `s` is in `[-125,125]`, `z` is in `[-125,5125]`, and
the same canonical transition-field encoding applies.

Every dot product and `z` fits in signed 32 bits. The two modular-multiplication
products fit in unsigned 64 bits and are smaller than the Goldilocks proof
field. The proof must establish the exact signed dot-product value and its
range, but consensus cannot mandate an instruction sequence or accumulator
type; a wider or mathematically equivalent implementation is valid. The full
allowed `z` interval has width 128,005,000, strictly less than `P`, so its
canonical residue uniquely identifies the exact integer. This is the defense
against the earlier search shortcut that discarded high accumulator bits by
reducing directly modulo 251.

## Succinct proof shape

The recommended proof is a non-zero-knowledge GKR/sumcheck argument backed by a
transparent multilinear PCS. Zero knowledge adds cost but no consensus benefit
for this public computation.

- Commit to the permanent base table and three weight-bank multilinear
  extensions described above.
- For a winning nonce, commit to activation and witness oracles for `X`, `S`,
  `E`, `Q2`, `R2`, `Q3`, `H`, `T`, and `V`, plus their range bits, split into
  the same three 128-layer segments. A segment is indexed by 7 layer bits, 7
  row bits, and 12 column bits.
- Prove each matrix product with the claim
  `S_l(r,c) = sum_k X_l(r,k) * W_l(k,c)`. The reduction over the 12 `k` bits is a
  degree-2 sumcheck. GKR batching must bind all 384 layers and both segment
  boundaries, not a sampled subset chosen before the transcript.
- Prove pointwise the signed-to-`P` encoding, both modular multiplication
  reductions, `h = 251*t + v`, and `X_(l+1) = v - 125`, including the virtual
  input layer. Range/lookup arguments must enforce the exact bounds above. In
  particular, field congruence without range proofs is insufficient.
- Batch the final PCS openings only after all commitments and claims have been
  absorbed into the Fiat-Shamir transcript. Canonically reject malformed field
  encodings, duplicate transcript forms, trailing data, replay under another
  block or model, and proof malleability.

Goldilocks is the base arithmetic field, but a single base-field challenge is
not the security target. Transcript challenges and random batching coefficients
must come from an extension or independent compound challenge space of at least
192 bits. A degree-4 Goldilocks extension is the conservative default because
`p^3` is slightly smaller than `2^192`. The complete parameter set must show at
least 128 bits of overall soundness after the union bound across sumchecks, PCS
openings, range arguments, and Fiat-Shamir reductions.

A sampled row check or plain Freivalds check is not a substitute for this
proof. Proof generation should occur only after the miner has computed a nonce
whose work digest meets the target; requiring a full succinct proof for every
losing nonce would make the proof system, rather than the matrix work, the
mining bottleneck.

## Final-activation BLAKE3 binding

The proposed mining digest retains a cheap pre-proof target test:

```text
final_activation_digest =
    BLAKE3-derive-key("CMFD/FORGEMATRIX/OUTPUT/V2",
                      challenge || u64_le(length) || canonical final_raw)

work_digest =
    BLAKE3-derive-key("CMFD/FORGEMATRIX/WORK/V2",
                      challenge || model_byte_root || model_PCS_root ||
                      final_activation_digest)
```

`canonical final_raw` is the row-major `B * D` table of `v` representatives,
each encoded as one byte in `0..=250`. `work_digest` is compared as an unsigned
256-bit big-endian integer with the chain-derived target.

The verifier cannot safely accept `final_activation_digest` as an unproved
miner claim. The feature-gated structured research proof now closes that gap
for both the current one-block Devnet output and power-of-two activation tables
through the production 524,288-byte shape as follows:

1. a BLAKE3 STARK privately authenticates the exact row-major `final_raw` bytes
   under the formula above, including every chunk compression, deterministic
   parent merge, root compression, and stack edge, so those bytes are no
   longer carried in the aggregate envelope;
2. the final digest, work digest, target, challenge, model roots, and table
   length are absorbed into the public transcript binding before the wiring
   verifier samples its cell point;
3. the STARK proves that the private bytes' cubic-Goldilocks multilinear
   evaluation at that point equals the PCS-authenticated opening of the last
   layer in the last output bank; and
4. the verifier recomputes `work_digest` from the proven final digest and
   pinned model roots and requires it to meet the block target.

This prevents a prover from substituting another final table or mining digest
without either breaking BLAKE3 or the sumcheck/PCS soundness. Proof or PCS
randomness is not included in `work_digest`, so it cannot provide a second
grinding surface.

The public-table bridge has therefore been removed from the aggregate format.
The tree backend uses a 120-row exact compression schedule, a deterministic
10-entry chaining-value stack, and a canonical transport that deduplicates
repeated Merkle authentication nodes before canonical zlib compression. The
complete tree-component envelope is capped at 256 KiB and rejects malformed or
noncanonical archives and compression streams. Deterministic release-mode
vectors measure 165,039 bytes for a 64-byte activation and 222,555 bytes for a
2,048-byte multi-chunk activation. With a log-size-seven final polynomial, an
isolated 32,768-row checkpoint measured a 209,693-byte compressed payload
(209,710 bytes with its outer envelope). That configuration has not yet been
timed; the earlier final-polynomial-zero run used about 12.22 GiB peak memory
and took 266.25 seconds.

At that 32,768-row shape on an RTX 5090, a separate unoptimized Cargo
test-profile comparison measured 348.28 seconds for CPU (64.503 setup, 283.416
prove; 238,698-byte canonical zlib payload) and 76.71 seconds with the now-wired
CUDA DFT plus Poseidon2 first-digest layer (7.700 setup, 68.551 prove; 237,292
bytes). That is 4.54x faster and 78% less wall time. The accelerated proof still
uses the unchanged CPU verifier. The hash-pinned proof-worker path has also been
tested with a 64-byte tree proof; the direct in-process API remains for trusted
development only.

CUDA ABI v1 is test-profile-only, with caps of `2^24` rows and `2^31` field
limbs. Production requires `2^27` LDE rows: widths 291 and 87 imply 291 GiB and
87 GiB inputs respectively, plus a 4 GiB first-digest layer. Streaming and an
out-of-core PCS/FRI and Merkle path therefore remain production requirements.

This does not establish production readiness. The production shape is
1,048,576 trace rows, and its complete proof size, peak memory, proving latency,
and verification latency have not yet been measured. The configured
production-shape component uses a cubic Goldilocks challenge field and its
security test requires at least 128 proven bits,
but the aggregate union-bound report, independent algebraic review, streaming
prover, consensus wire tag, and audits remain explicit gates.

The feature has no consensus proof tag and does not satisfy the production
proof-size, streaming, soundness, or audit gates. A proof of the matrix and
cubic relations that omits a sound final-digest binding is not a valid block
proof.

## What the proof cannot establish

The argument proves evaluation of the committed function. Software consensus
cannot prove that the raw bytes physically resided in GPU VRAM, that a GPU was
used, or that a particular instruction sequence executed. A conforming miner
may stream the artifact from host memory or use a CPU, FPGA, ASIC, or a more
efficient equivalent algorithm.

The intended defense is economic: the unverified design hypothesis is that the
6 GiB bank and repeated dense access make resident GPU execution the fast path
on a 16 GiB card. Hardware
attestation could be offered outside consensus, but it would add vendor trust,
exclude much consumer hardware, and still would not replace the arithmetic
proof.

No VRAM minimum exists in consensus. An 8 GiB device may retain the raw mining
bank while staging proof data elsewhere; 2--6 GiB devices may tile or stream
from host RAM or storage. All remain valid if they compute the exact relation.
Complete winning-proof memory and speed are unmeasured, and mining eligibility
is separate from whether a card can host a particular paid inference model.

Activation therefore requires a reproducible comparison using identical nonce
vectors: fully resident, double-buffered pinned-host streaming, pageable-host
streaming, on-the-fly lossless regeneration/decompression of the exact v2
artifact if any is discovered, and the best compressed/decode path. Treat v1
seed regeneration only as a separate historical negative control because it
cannot reproduce the seedless v2 bank. Test both enforced 2, 4, 6, and 8 GiB
caps and representative physical cards. Pin PCIe generation/link width, CPU,
host-RAM topology and speed, storage, driver, clocks, and power limits. After a
30-second warmup, run at least five randomized 120-second trials. Record median
and p95 nonce time, setup time, host-to-device bytes, peak VRAM, host RSS,
power, and energy. The resident path must be at least four times faster than
the best valid <=4 GiB or nonresident path on every named baseline card, or the
profile must change.

## Activation and benchmark gates

Mainnet remains disabled until all of these gates have reproducible evidence:

- a complete proof implementation for all 384 layers, range constraints, model
  link, final-activation digest, block challenge, nonce, and target;
- peak device allocation no greater than 13.5 GiB on supported 16 GiB cards,
  measured end to end rather than inferred from model size;
- winning-nonce proof generation below 10 seconds, with a target below 5
  seconds, without changing the proved relation;
- proof size at most 256 KiB, with 64 KiB as the stretch target, and an explicit
  separate cap for total proof plus public witness bytes;
- proof verification below 100 ms on a specified ordinary CPU core;
- at least 128 bits of documented total soundness with at least 192-bit
  transcript challenges;
- two independent prover/verifier implementations with byte-for-byte canonical
  vectors and CPU/GPU arithmetic differential tests;
- adversarial tests for skipped layers or output, seed/regeneration shortcuts,
  sparse or malformed model data, false byte-root/PCS links, invalid ranges,
  transcript substitution, replay, malleability, target confusion, and
  arithmetic divergence;
- audits by at least two independent teams and a public, incentivized testnet.

## Repository implementation status

`cmfd-consensus` retains the ForgeMatrix v1 full-recomputation oracle only for
comparison. The v2 research code now implements:

- a seedless model-bank format, bounded fixture builder, and 64 KiB-buffered
  verifier for canonical lengths, bytes in `0..=250`, BLAKE3 roots, and
  manifest-selected PCS identity fields;
- a tiny-profile exact integer witness generator/checker for initialization,
  every GEMM, affine masks, signed transition-field encoding, two modular
  multiplication reductions, output reduction, centered activation encoding,
  final digest, and block target;
- a standalone Fiat--Shamir matrix-multiplication sumcheck skeleton with
  canonical Goldilocks field representatives in transcript hashing,
  commitment/transcript mutation tests, and a hard 4096-element research cap;
- custom bank-batched matrix and transition/range sumchecks in the cubic
  Goldilocks extension. They prove every matrix product and all 121 local
  transition/range constraints over the actual ForgeMatrix trace, with
  canonical bounded encodings and exact no-wrap bounds. A successor-wiring
  argument and fail-closed aggregate verifier bind initialization, every layer
  edge, bank boundaries, fixed model commitments, and the final bank output;
  the frozen protocol and remaining work are in
  [forgematrix-custom-proof.md](forgematrix-custom-proof.md);
- an optional `whir-prototype` aggregate explicit-point PCS experiment. It
  stacks bounded Goldilocks tables under one transparent commitment, supplies
  per-table commitment aliases to every component before transcript sampling,
  and verifies the complete canonical opening set under a requested 128-bit
  unique-decoding WHIR configuration. Its version-2 fixed-width native codec
  derives all shapes from the trusted configuration and deduplicates Merkle
  nodes in canonical first-reference order. Ten 13-variable explicit
  envelopes measured 188,104 through 190,024 bytes and passed the unchanged
  verifier;
- an optional `dory-bls12-381-prototype` backend with deterministic,
  identity-pinned BLS12-381 setup, canonical distinct-point aggregation, an
  exact bank-batched matrix sumcheck, a seven-constraint scalar arithmetic
  transition sumcheck, and a packed successor-wiring argument. Witness-free
  fixture proofs are 11,539, 23,171, and 14,529 bytes respectively; their n=31,
  n=33, and n=29 production grammars project to 70,483, 74,979, and 64,097
  bytes. Exact-target
  APIs now high-zero-pad all three to a shared n=33 geometry and reject layout
  mismatches. One opening payload at n=33 projects to 70,639 bytes, but the
  uncompressed production composition has 480 direct claims against the current
  128-claim bound. A scalar range LogUp now reuses the transition commitment:
  three openings prove membership, and one randomly combined selector-sumcheck
  opening binds the 98 digit lanes' value/slack reconstruction to the eight
  regular source roles. Its n=10 fixture is 25,985 bytes and its n=33 grammar
  projects to 78,529 bytes. Four arithmetic proofs need 48 claims and four range
  proofs need 16; matrix and wiring bring the compressed subtotal to 104 claims.
  A composed verifier requires each arithmetic/range pair to share one packed
  commitment.
  Eleven Fiat-Shamir equality points add 22 authenticated claims linking the
  pinned base input to the virtual transition, the initialization output, and
  each bank's matrix activation, matrix accumulator, and transition activation
  to their corresponding transition or wiring roles. The matrix weight
  commitments are checked directly against the trusted BLS fixed-model identity.
  A canonical shared frame authenticates the exact three-matrix,
  four-transition, one-wiring production topology with one 126-claim aggregate
  and projects to 133,373 bytes at n=33. Altered model commitments, equality
  values, and substituted, reordered, or omitted components reject.
  The authenticated model-bank stream now derives the BLS commitments
  incrementally and publishes them only after full bank verification; bounded
  fixtures match the in-memory commitment path and reject corrupt, trailing, or
  reordered input. The final Dory opening now combines committed rows through
  a one-row buffer without materializing a combined coefficient table, while
  repeated aggregate claims share polynomial folds and allocate no equality
  tables. An explicit scratch path keeps every post-challenge fold in a
  self-authenticating artifact, aborts on storage corruption without a dense
  fallback, and preserves complete shared-layout proof bytes. A row-source
  constructor now writes canonical authenticated source prefixes while
  computing the unchanged commitments. The verified model-bank sink now
  transactionally publishes reusable base and ordered weight coefficient
  artifacts only after roots, lengths, and EOF authenticate. Matrix proving
  consumes those artifacts directly, matches the materialized proof exactly,
  and rejects a commitment from the wrong bank before proving. Each artifact
  authenticates its logical and explicit lengths, and every fold keeps the
  remaining zero tail implicit instead of allocating or writing it. The
  scratch-enabled shared path uses it for every matrix, fixed-base, transition,
  LogUp, and wiring commitment, without power-of-two-padded coefficient copies.
  Wiring additionally reads its
  signed tables directly for commitment and multilinear evaluation, and the
  transition commitment derives all 110 regular and radix-16 lanes directly
  from its witness. The transition arithmetic sumcheck also keeps selector
  weights implicit and folds 12 live lanes in authenticated 16-scalar scratch
  rows. The shared prover reuses that exact authenticated transition artifact
  in LogUp, and the aggregate folds and streams cloned handles only once. A
  mismatched same-shape artifact is rejected. Canonical, self-authenticating
  formats support either a literal-scalar prefix or signed/unsigned
  32- or 64-bit words followed by dictionary codes. The transition stores twelve
  consensus-bounded lanes as 32-bit words and its 98
  radix-16 lanes as checked `0..15` bytes. LogUp's inverse coefficients are
  restricted to zero plus sixteen `1 / (alpha - digit)` values. A
  challenge-bound mapped view reuses the transition's authenticated digit
  codes instead of writing a second coefficient file. Every read authenticates the complete header, dictionary,
  words or literal scalars, codes, digest, length, and EOF. Differential tests match the
  former 32-byte-scalar artifacts' commitments, claims, and exact proof bytes
  and reject corruption, truncation, non-canonical scalars, and forged codes.
  Exact production projections put the transition at 9,797,894,776 bytes,
  about 9.125 GiB including framing, and the mapped inverse at zero additional
  coefficient-file bytes. One retained transition/range pair is therefore about
  9.125 GiB and all four are exactly 39,191,579,104 bytes, about 36.5 GiB,
  instead of 1.76 TiB.
  LogUp streams its inverse commitment and folds cell-variable rounds in linear
  work. Its first authenticated lineage stores regular selectors as one scalar
  and range cells as one-byte codes for two original radix-16 digits. The next
  three generations use two-, four-, and eight-byte codes for four, eight, and
  sixteen digits. The header binds the transcript context, reconstruction
  challenges, dimensions, parent digest, and complete payload. Each reader
  reconstructs the exact transition and inverse scalars from the bound digit
  sequence, and generation five returns to the ordinary bounded-I/O fold
  artifact. LogUp retains only the 128 production
  selector-boundary values, and streams reconstruction evaluations. Dense and
  scratch outputs match exactly. Commitment rows now execute in deterministic
  parallel batches behind a bounded 256 MiB coefficient window, while source
  reads, artifact writes, and target-group accumulation retain canonical order;
  the authenticated model-bank writer now uses that same row-batch boundary
  across arbitrary verified input chunks. Three n=19 release A/B repeats gave
  serial and parallel medians of 822 and 385 ms, respectively, a 53.2%
  reduction, with identical artifact digest, commitments, claims, and proof
  bytes. The mapped inverse computes the sixteen dictionary inverses once and
  reuses the transition's exact radix-16 codes. Dory MSM and elementwise vector
  routines are CPU-parallel and preserve the normalized group elements and
  proof bytes. A consuming aggregate boundary now derives the sumcheck,
  combined row commitments, and `L^T M`, then releases deferred coefficient
  artifacts before the final Dory reduction. Direct testing preserves exact
  proof bytes, and standalone n=15, n=17, and n=19 runs leave zero scratch after
  completion. At n=19 the release/regeneration run took 9.480 seconds proving versus
  42.699 seconds for the buffered serial-row checkpoint and 53.948 seconds for
  the rejected recomputation path. Releasing the source reduced scratch from
  795,900 bytes to 644 bytes; exact regeneration took 2.267 seconds and restored
  795,900 bytes before the 7.043-second aggregate opening. Verification took
  2.381 seconds, the proof remained 47,729 bytes, and final scratch was zero.
  Linear n=33 extrapolation gives roughly 1.80 CPU proving days, 10.32 hours per
  regenerated source (1.72 days for four sequential sources), and 1.34
  aggregate-opening days. Exact projection puts the four compressed
  lineages at 15.06, 9.06, 6.06, and 4.56 GiB. Their maximum overlap is the
  first two at 24.125 GiB; the first ordinary scalar child is delayed until
  generation five. The shared prover now retains the exact compact artifact
  identity, releases each completed pair source before constructing the next
  lineage, and regenerates all four sources before shared openings. Regeneration
  writes only canonical words and codes, reuses the original Dory commitments,
  and aborts unless the complete BLAKE3-authenticated artifact matches. A changed
  witness is rejected. The projected transition/range storage peak is therefore
  39,191,579,104 bytes, about 36.5 GiB, rather than 72.62 GiB: one source plus
  the largest lineage overlap is about 33.25 GiB, while four regenerated sources
  before aggregation are larger. The aggregate now recognizes each transition
  and mapped inverse that shares a compact source, reconstructs their first eight
  folds as authenticated role-bound logical views under the exact aggregate
  challenges, and writes no packed aggregate-fold artifact for those rounds. Fold
  nine returns to ordinary scalar lineages. Dense, ordinary scratch, and compressed
  paths produce the same proof bytes; corruption aborts and cleans the source. Two n=19
  release runs retained the 47,729-byte proof and measured the same 2,377,688-byte
  opening peak, down from 18,819,084 bytes by 7.91 times. Accumulator sources
  retain canonical signed 64-bit words instead of expanded field scalars.
  Activation, wiring, and model-weight sources retain the first Dory row as
  signed words and encode every remaining bounded `[-125, 125]` value as one
  authenticated dictionary byte.
  Challenge-bound logical views avoid writing their first eight fold artifacts.
  A complete three-bank n=19 shared-layout run preserved the 84,717-byte proof,
  measured 92.212 seconds proving and 7.045 seconds verification, matched its
  6,866,772-byte aggregate scratch projection exactly, and ended with zero scratch.
  Encoding the twelve bounded transition lanes as authenticated 32-bit words
  reduces transition sources from 39,159,073,248 to 29,470,231,008 bytes.
  Retained sources are now 38,217,643,300 bytes and the ordered fold peak remains
  3,297,676,512 bytes. The complete n=33 aggregate-stage projection is therefore
  41,515,319,812 bytes (about 38.7 GiB), down 10.57 times from
  438,943,885,320 bytes (about 408.8 GiB) and 18.92% from the immediately
  preceding projection. Further reduction or distribution and a
  complete measured n=33 run are still required;
  a fresh complete n=19 release run preserved the 84,717-byte proof, measured
  104.635 seconds proving and 8.861 seconds verification,
  observed a 49,434,524-byte full-prover scratch peak against a
  2,311,140-byte aggregate-stage projection, and retained zero scratch;
  independent soundness review and audit also remain activation gates. The
  executable BLS algebraic report uses exact
  nonzero-scalar rejection sampling and bounds the production numerator at
  19,781,388,244 over at least 2^254 challenges: a 219-bit algebraic floor with
  91 bits of proof-attempt grinding headroom above the 128-bit requirement.
  Dory knowledge soundness, Fiat-Shamir, and implementation review remain
  fail-closed gates;
- a version-3 structured envelope that replaces the bounded public final table
  with a BLAKE3 STARK, absorbs the challenge/model
  roots/digests/target/length before sampling, links the private hash input to
  the authenticated last-layer opening, recomputes work, and rejects high work;
- exact BLAKE3 chunk, parent, root, counter, flag, and chaining-value-stack
  constraints through the 524,288-byte production output shape, plus a
  canonical Merkle-path dictionary and canonical compressed component envelope
  capped at 256 KiB;
- an optional, feature-gated Remainder CE GKR/Ligero proof of the complete tiny
  2x4x4 relation. It binds the fixed model, public statement, target, nonce,
  masks, all matrix products, every nonlinear reduction and range, final public
  activation, and work digest. Tampering with those fields or the transcript is
  rejected;
- Rust and CUDA v2 arithmetic smoke vectors that compare initialization and
  every layer after applying fixture-supplied mask coefficients.

Consensus also has canonical bounded, network-aware transaction/proof/block
wire encodings and network-parameter-bound `Block`/`ChainState` validation.
Proof tag 1 carries the legacy v1 proof and tag 2 carries a tiny v2 compact
claim. Devnet-0 uses the tag-2 path with dimension 4, batch 2, and 4 layers.
The compact claim carries identity and digest fields rather than every witness,
but its verifier reconstructs the full witness and recomputes every tiny-model
layer from the pinned model bytes and nonce. It is compact on the wire, not a
succinct argument or a production proof.

The PCS fields remain opaque manifest values. The toy sumcheck verifier still
receives the full matrices to recompute multilinear openings, uses only the
64-bit base field, and is not the proof used by the Devnet-0 block verifier. It
is neither succinct nor production-sound. The production-sized v2 constructor
is hard-disabled.

The complete tiny Remainder experiment is also not a candidate consensus
backend. With release optimizations on the development host it produced a
302,726,694-byte transcript in 49.76 seconds and took 122.63 seconds to verify.
It therefore fails both the 256 KiB proof-size gate and the 100 ms verification
gate by orders of magnitude. Its pinned research backend is unaudited, retains
panic paths, and assigns circuit identities at runtime rather than providing a
canonical cross-process circuit artifact. The wrapper's 384 MiB cap and panic
containment are research safeguards, not acceptable network-parser bounds.
There is no proof wire tag or `ChainState` integration for this feature.

The main-trace generator now exposes a bounded row-at-a-time sink and
propagates an early sink failure without generating the remaining rows. This
does not make the current Plonky3 PCS/FRI prover streaming: it still collects
the complete trace and materializes the LDE in memory. The repository does not
yet implement that production out-of-core prover, the raw-byte-to-PCS
model-link certificate, the final aggregate soundness report, or a full
production-size BLAKE3 proof benchmark. The exact tree relation and bounded
compressed component transport are implemented, but only smaller and
intermediate shapes have been proved below 256 KiB; the 1,048,576-row
production shape remains an activation measurement. The aggregate proof has
no consensus wire tag and the WHIR and BLAKE3 backends remain unaudited
research code. The mining CUDA fixture remains a differential harness, not a
tensor-core succinct prover or evidence of residency. The proof CUDA path
accelerates DFT, LDE, and the first Poseidon2 digest layer, but its monolithic
ABI is not a production low-VRAM or out-of-core prover.
The CUDA oracle does not independently rederive the BLAKE3 mask coefficients;
an independent challenge-to-coefficient implementation and a broader vector
corpus remain required.

The unified 439-column trace cannot be made production-sized by silently
changing WHIR parameters. With nine selector variables folded first,
Goldilocks two-adicity caps the starting log-inverse rate at six. The
non-conjectural 128-bit unique-decoding schedule needs 536,576 initial-value
bytes with no grinding and 471,040 with the practical 16-bit ceiling, already
above the complete 262,128-byte payload before paths or sumchecks. Reducing the
opening enough would require at least 67 grinding bits. CapacityBound can fit
only by accepting an explicit Reed-Solomon capacity/correlated-agreement
conjecture, while the fitting JohnsonBound comparison requires 48-bit
grinding. Both remain rejected activation paths.

The replacement layout removes the principal width source without weakening
that policy. It retains 47 ordered core columns. The first four-column,
64-row transpose is now an explicit rejected V1: its raw bank trace reaches
`n=32`, but FRI log blowup four requires an `n=36` LDE, beyond Goldilocks
two-adicity. V2 instead packs two range specifications into each of four rows
per cell. Twenty-eight digit columns are divided among seven four-query nibble
buses, with seven table-multiplicity columns. Main widths are 46 for
initialization and 47 for each bank. The bank trace is `n=28` and its FRI LDE
is exactly `n=32`. Canonical row generation and layout binding under digest
`88f2f31f6f9d4aca4a69bc2ac6dfd88bcf670c3ed803e0fb24a241f791372cb3`
are implemented. The reusable preprocessing topology has width 66 and zero
challenge-dependent columns: the previous 40 columns plus 7 layer, 7 row, and
12 column bits. Its initialization and bank plan digests are
`5b2b1251538d96ebc8eb5a9f3a6ecdb314a3de73d15b3ef60643db84af84811e`
and `c5c2d698f1cbdf016d5272ec4c574314fef63653ebeb62e460bb45b11640fa75`.
Those are structural identities, not PCS roots. The AIR uses the authenticated
coordinate bits to select the challenge-derived affine mask coefficients, so
no per-block mask table or separate mask opening is needed. The production-
sized payload still has to be proved and measured.

The transition and range reduction now has a bounded test-only proof. On 128
cells, the AIR binds the challenge-derived mask and enforces all seven
transition equations. Eight source buses bind every core source/slack pair,
and seven nibble buses range-check four packed digit columns apiece against the
fixed table. The pinned proof has maximum degree nine, 145 constraints, three
quotient splits, and 48 base-field lookup auxiliary openings at each local and
next evaluation. At FRI log blowup four it reaches the configured 128-bit
list-decoding target with 57 queries, one above the measured minimum, and
bounds the shared-pair lookup-challenge error below `2^-163` from 288,388,719
counted bad roots. Every core column plus adversarial packed-witness, topology,
table, and degree mutation fails. Its 512-row bincode baseline is 222,960
bytes; repeated best-zlib encodings measured 160,461 to 160,667 bytes under a
tested 165,000-byte ceiling. That diagnostic is neither a production codec nor
a production-shape bound.

More importantly, the production `n=28` geometry cannot guarantee the
262,128-byte native proof cap with ordinary batch-STARK FRI. A valid 57-query
transcript spread across distinct six-bit prefix buckets has a 333,792-byte
lower bound even with globally deduplicated Merkle paths, exceeding the cap by
71,664 bytes before roots, proof-of-work witnesses, lookup terminals, input
commitment paths, or headers. The compact reduction remains valid, but its
production transport requires a different succinct commitment or aggregation
layer. Production component wiring, canonical encoding, aggregate measurement,
and verification remain gates.

Implementing any subset of those components must not make the v2 profile
activatable. Activation is a separate consensus change after every gate above
is satisfied.
