# Security policy

ForgeMatrix and the CMFD monetary rules are consensus-critical research code.
Do not deploy this repository as a public-value mainnet.

The recommended ForgeMatrix v2 relation and its unresolved boundaries are
documented in [docs/consensus/forgematrix-v2.md](docs/consensus/forgematrix-v2.md).
Its production profile is a design target, not an activation notice.

The repository now has canonical, bounded, network-aware wire decoding for
transactions, tagged v1/v2 proof envelopes, and blocks. Devnet-0 can accept the
tiny v2 compact claim through network-parameter-bound `Block`/`ChainState`
validation. That claim is not a succinct argument: the verifier recomputes
every layer of the tiny pinned model. The production profile remains disabled.

An optional `remainder-prototype` feature now proves the complete tiny 2x4x4
relation with the exact pinned Remainder CE revision
`5687fe7f3a077c75c374422ef79f22e3860de9c1`. It binds the fixed model, block
challenge, target, nonce, masks, all matrix products, every nonlinear
transition and range, the final activation, and the work digest. A release-mode
local benchmark produced a 302,726,694-byte transcript in 49.76 seconds and
verified it in 122.63 seconds. Those results disqualify this generic backend
from consensus: they exceed the 256 KiB proof gate and 100 ms verification gate
by orders of magnitude. The feature is a research and adversarial-correctness
oracle only; it has no wire proof tag and is not accepted by `ChainState`.

The pinned backend is unaudited, contains panic paths, does not provide a
canonical cross-process circuit artifact, and exposes the tiny fixed model as
verifier-known public input rather than proving the production raw-byte-to-PCS
link. The wrapper imposes a research-only byte cap, rejects trailing and
noncanonical encodings, pins the proof configuration, and contains backend
panics, but those mitigations do not make it a network-safe verifier. Production
work must use a custom batched matrix/transition sumcheck with a transparent
PCS and a separately hardened bounded parser.

The replacement custom path now has bank-batched matrix, transition/range, and
successor-wiring arguments over the cubic Goldilocks extension. They reduce the
actual four-layer Devnet trace to a 556-byte canonical matrix transcript, an
8,381-byte transition transcript, and a 308-byte wiring transcript before PCS
openings. The transition argument
mixes 121 equations over 110 regular/range-digit oracles, range-proves the
signed accumulator, checks the challenge-derived mask polynomial, and rejects
incorrect quotients, signs, ranges, activations, rounds, bindings, and
encodings. The transition argument also covers the reserved virtual-input
layer. The wiring argument binds its initialized activation, every within-bank
successor, and both production bank boundaries through logarithmically many
opening claims, and checks that its activation commitments are the same
commitments used by the matrix and transition components. The aggregate
research verifier now also requires the matrix accumulator to equal the
transition input, pins the base table and model-weight commitments, binds the
declared final-bank output commitment, strictly parses a 5 MiB-capped envelope,
and fails closed unless configured PCS and final-hash verifiers authenticate
every canonical opening claim. An optional `whir-prototype` feature now commits one
or more bounded Goldilocks tables under one transparent BLAKE3 Merkle/WHIR root
and authenticates the exact independent cubic-extension MLE points emitted by
the custom sumchecks. Its proof bytes are bounded, canonically re-encoded,
trailing data is rejected, and verification panics are contained. The same
feature now replaces the aggregate's public final-activation table with a
BLAKE3 STARK. Small inputs retain the original one-block research AIR; larger
power-of-two tables use an exact chunk/parent/root tree AIR that matches the
upstream derive-key result through the production 524,288-byte shape. The tree
proof privately hashes the final bytes and proves that their cubic-Goldilocks
multilinear evaluation equals the PCS-authenticated last-layer opening. The
challenge, model roots, target, digests, and table length are bound before that
opening point is sampled. This closes the research aggregate's
untrusted-final-digest gap without adding proof randomness to the mining digest.

The tree transport deduplicates repeated Merkle authentication nodes using a
canonical first-reference dictionary and then applies canonical zlib
compression. It rejects noncanonical dictionaries, malformed lengths,
out-of-range references, trailing bytes, noncanonical compression, and
decompression beyond the bounded native-proof limit. The complete component
envelope is capped at 256 KiB. Deterministic release-mode vectors measure
165,039 bytes for a 64-byte activation and 222,555 bytes for a 2,048-byte
multi-chunk activation. A 32,768-row resource checkpoint measured a 233,382-byte
compressed payload (233,399 bytes with the outer envelope), about 12.22 GiB
peak memory, and 266.25 seconds proving time.

The optional `gpu-proof-prover` experiment accelerates the prover's exact
Goldilocks DFT/LDE operations and the value-MMCS Poseidon2 first digest layer.
It does not change the Goldilocks modulus, transform or coset semantics,
transcript, CPU verifier, or consensus rules. CUDA selection requires an
explicit library path and device; there is no environment search or fallback
after GPU selection. Every fully encoded accelerated proof is verified by the
unchanged CPU verifier before it can be returned. CPU/GPU tests compare logical
and physical bit-reversed layouts, transformed coset LDEs, commitments,
openings, and final polynomials. Complete proof bytes are not required to match
because the parallel FRI grinding search may select different valid nonces.

The direct accelerated API loads the explicitly named native library in the
calling process and is a trusted-development interface only. CPU proof
verification detects wrong arithmetic but cannot contain memory corruption,
hangs, or process compromise. A caller can instead use the short-lived
`cmfd-proof-worker`, which adds bounded canonical IPC, caller-pinned SHA-256
hashes, a deadline, output limits, and whole-process-tree termination through a
Windows Job Object or Unix process group. The hash-pinned worker path has been
tested with a 64-byte tree proof, and the parent independently verifies the
returned bytes. This contains ordinary crashes and descendants, but it is not
an OS sandbox: same-user file replacement between hashing and loading,
transitive native dependencies, and host-wide resource exhaustion remain
outside this boundary. No wallet or node path enables either experimental path
by default.

The node has a separate operator-enabled verifier-worker mode for externally
submitted blocks. It reuses the hash-pinned executable and process-tree
containment, adds an explicit wall-time limit and a Windows Job Object memory
limit or Unix address-space limit, and transports only canonical bounded block
bytes plus identities for the exact verifier and statement. A successful
response is accepted only when both identities match. The worker outcome is a
local trust boundary: unlike proof generation, the parent cannot repeat the
expensive verification without defeating isolation. Operators must therefore
pin a trusted executable and protect its path and account. This mode is crash
and resource containment, not a defense against same-user code replacement or
a compromised host, and it currently supports only Devnet's V2 reference
verifier. V3 remains fail-closed.

The exact Poseidon2 CUDA first-digest layer is now used by proof generation for
the value MMCS. Merkle parent compression, shorter-matrix injection, openings,
transcript operations, and all verification remain CPU work. At the 32,768-row
checkpoint on an RTX 5090, the same unoptimized Cargo test profile took 348.28
seconds on CPU (64.503 setup, 283.416 prove; 238,698-byte canonical zlib
payload) and 76.71 seconds with CUDA DFT plus Poseidon2 (7.700 setup, 68.551
prove; 237,292 bytes): 4.54x faster and 78% less wall time.

The monolithic Poseidon2 CUDA ABI v1 remains test-profile-only. The independent
`proof_stream` ABI v1 instead holds ordered source coefficients on the selected
device and emits exact physical-bit-reversed LDE rows plus unpadded Poseidon2
digests through a monotonic bounded cursor. Its limits are 64 equal-height
matrices, source height `2^20`, seven added bits, `2^27` output rows, 4,096 total
columns, `2^31` input limbs, and power-of-two chunks no larger than `2^16` rows
that cannot cross a source-height coset block. At `32,768 x 291`, `+7`, the
digest-only stream phase measured 308.345 ms and 13.60 million rows/s on an RTX
5090 while avoiding a 9.094 GiB host LDE.

The worker spill writer accepts each global physical row exactly once, binds
the job plus every ordered matrix width and coset shift, aggregate geometry,
physical layout, and canonical little-endian limbs into BLAKE3, synchronizes
and validates the complete file, and publishes without overwrite only after
sealing. Normal error and drop paths remove the partial artifact; abrupt process
termination may leave an unpublished `.partial` file for operator cleanup.
Readers authenticate the header, exact length, full checksum, and every
fixed-size chunk used by a later row read. This protects worker storage
integrity only. It neither
replaces the unchanged CPU proof verifier nor makes accelerator output trusted.

This is still not a production succinct solution. The full production AIR has
1,048,576 rows and has not yet been proved end to end; its final proof size,
peak memory, proving time, and verification time remain unmeasured. A test
derives the production-shape AIR constraint count and degree over a cubic
Goldilocks challenge field and requires at least 128 proven bits under
Plonky3's component-security model, but this is not the missing aggregate
union-bound report. The legacy one-block backend and the
new custom tree AIR both require independent algebraic review. Bounded trace
generation, the CUDA row stream, and sealed spill storage now exist, but the
current WHIR adapter consumes only an authenticated initial source,
codeword/tree commitment, and streamed fold-two initial sumcheck. Later folded
rounds, FRI, and opening generation are not yet fully out of core. There is
now a fail-closed raw-model-byte-to-authenticated-source bundle: one verified
stream stages the production `n = 19` base role and `n = 31` weight roles and
publishes a single manifest pointer only after every role seals. Exact initial
codeword construction, typed demand trees, and the V2 role join now bind each
prepared role to its pinned PCS commitment alias. A complete production-scale
run through extension encoding, openings, and verification is still absent, so
there is no activation certificate, consensus tag, complete soundness report,
or audit.
The publication pointer is untrusted storage: a separately retained canonical
bundle identity pins the exact bundle and every source-artifact digest on each
reopen, including after restart. A self-consistent pointer/object replacement
without that retained identity is rejected.
Abnormal termination can leave roughly 48 GiB of unreachable staging/object
data, and portable directory-entry power-loss durability is not implemented;
reopening is fail-closed, but lock-aware recovery and filesystem durability are
still production gates.
The aggregate remains feature-gated research scaffolding with no consensus or
wire tag. See
[docs/consensus/forgematrix-custom-proof.md](docs/consensus/forgematrix-custom-proof.md).
The optional `dory-bls12-381-prototype` feature now exercises a real BLS12-381
Dory opening with deterministic, role-separated hash-to-curve setup generators
and a pinned setup identity. Its n=8 compressed opening payload is 16,909 bytes,
and its distinct-point aggregate produces a 17,695-byte proof for three n=8
claims. The fixed parser preflights the full shape and tests reject statement,
order, setup, sumcheck, and proof mutations. The n=31 grammar projects to 66,559
bytes, but the executable prover is still capped at n=16. This remains a
sequential, unaudited backend checkpoint; the complete production aggregate is
not ported and consensus does not accept it. Cross-field tests now evaluate
all 121 bounded transition constraints directly in the BLS12-381 scalar field,
including signed boundaries and invalid reductions/digits; this establishes
arithmetic portability, not a complete proof of those constraints.
The BLS matrix checkpoint now retains distinct activation, model-weight, and
accumulator commitments, runs the exact degree-two common and degree-three layer
sumcheck, and authenticates all three terminal evaluations with one aggregate.
Its executable n=3 fixture is 11,539 bytes, including a 9,439-byte Dory proof.
The production n=31 grammar projects to 70,483 bytes, including a 66,559-byte
aggregate, and pins the matrix sumcheck numerator at 45 plus a 26-variable
random-point relation reduction. Unequal table
geometries, every transcript role, and the canonical outer parser have mutation
coverage. The shared layout now checks each weight commitment against a trusted
BLS fixed-model identity bound to `ModelPcsIdentity`. The model-bank verifier now
feeds its authenticated, ordered field stream directly into incremental Dory row
commitments and publishes the resulting identity only after roots, exact length,
and EOF verify. The streamed and in-memory commitments agree on an executable
fixture; corruption, trailing bytes, role reordering, and noncanonical field
values reject. Production still needs the final model artifact streamed through
the n=33 setup to publish its network-pinned commitments, plus soundness review
and audit.
The BLS arithmetic transition checkpoint now proves the seven regular
constraints with degree-three rounds and authenticates twelve terminal roles as
selector-qualified points under the commitment that still packs all 110
oracles. Its canonical outer proof is 23,171 bytes for an executable n=10
fixture. The same grammar projects to 74,979 bytes for the production n=33
transition table. A composed verifier requires this arithmetic proof and the
range proof below to carry the exact same commitment. The verifier is
witness-free, and tests reject statement, mask, round, terminal, commitment,
opening, length, and trailing-byte mutations. This still does not provide a
streamed n=33 prover, independent review of the executable soundness analysis,
or an audit.
The scalar wiring checkpoint packs the initial activation plus three input/output
bank pairs into eight selector slots under one Dory commitment. It authenticates
all initialization, within-bank successor, and cross-bank boundary evaluations.
Its executable two-bank n=6 fixture uses nine openings and is 14,529 bytes. The
production n=29 grammar uses 31 openings and projects to 64,097 bytes, including
a 62,479-byte Dory aggregate. The verifier is witness-free and mutation tests
cover the binding, statement, commitment, every evaluation, transcript, opening,
and outer parser. The shared layout below now links the scalar matrix and
transition commitments to these wiring roles; n=29 streaming, soundness review,
and audit remain gates.
The shared-layout checkpoint now pins all scalar components to an exact
verifier-selected variable count. High-zero padding preserves each component's
natural multilinear coordinates, while canonical decoders reject a proof made
for any other geometry before opening verification. An executable n=10 fixture
proves and verifies matrix, arithmetic transition, range, and wiring at one
layout with 54 claims and one 21,775-byte Dory payload. Its complete canonical
frame is 35,953 bytes. The shared grammar admits the exact production topology
of three matrix proofs, four arithmetic/range transition pairs, and one wiring
proof. Eleven Fiat-Shamir equality points link the fixed base input to the
virtual transition, the initialization output to wiring, and, for every bank,
link matrix activation to wiring input, matrix accumulator to transition input,
and transition activation to wiring output. Each equality opens both
independently committed representations. A random combination of the two range
reconstruction identities reduces the former 480 direct claims to 104; the 22
link claims bring the aggregate to 126, below the unchanged 128-claim cap. The
grammar binds the trusted model identity, every transcript digest, ordered claim,
and link evaluation, and rejects altered model commitments, links, and omitted or
reordered components. Production is pinned to n=33. The complete production
frame projects to 133,373 bytes, including one 70,639-byte shared Dory payload.
The scalar range checkpoint now reuses the exact packed transition commitment,
commits the sixteen table multiplicities before sampling `alpha`, and commits
an inverse polynomial afterward. A degree-four sumcheck proves the inverse,
rational-sum, support, and total-count identities; three Dory openings
authenticate the transition, multiplicity, and inverse evaluations. One
Fiat-Shamir-random combination of the source and digit reconstruction identities
is proved by a degree-two selector sumcheck and adds one transition opening. The
n=10 fixture is 25,985 bytes,
including a 21,775-byte Dory proof, and rejects both an out-of-table digit and
an in-range digit that no longer reconstructs its source before proof emission.
The complete n=33 range grammar projects to 78,529 bytes, including the shared
70,639-byte opening payload. Across four transitions, arithmetic needs 48 claims
and range needs 16; adding nine matrix and 31 wiring claims gives a compressed
subtotal of 104. The composed transition verifier requires arithmetic and range
proofs to share one commitment. The shared layout adds 22 fixed-model and
cross-component equality claims and authenticates all 126 claims with one opening
proof. Transcript v2 now rejection-samples exactly uniformly from nonzero
BLS12-381 scalars. The executable production union-bound report includes every
matrix relation and sumcheck, transition reduction, LogUp rational-identity and
sumcheck term, reconstruction reduction, wiring identity, equality link, and
distinct-point aggregation term. Its conservative algebraic numerator is
19,781,388,244 over at least a 2^254 nonzero challenge space, establishing a
219-bit algebraic floor and 91 bits of proof-attempt grinding headroom above the
128-bit target. The dominant term conservatively grants each invalid LogUp
multiset one root per active range value plus all sixteen table values. Dory
knowledge soundness, the BLAKE3 Fiat-Shamir reduction, and the implementation
have not been independently reviewed; those computational assumptions are not
silently included in the algebraic number. Final-model commitment publication,
n=33 prover streaming, production benchmarks, independent review, and external
audit remain required.
The separate `production-whir-candidate` parser profile admits exact n=19/n=31
configuration geometry but intentionally rejects n=31 at the byte gate: its
268,640-byte dictionary-free floor is larger than the entire 262,128-byte proof
payload before dictionary and aggregate bytes.

Mainnet remains disabled until all of the following are complete:

1. A frozen production ForgeMatrix specification, a frozen canonical encoding
   for the production public inputs, and concrete total
   soundness of at least 128 bits after all union bounds and Fiat-Shamir
   grinding assumptions.
2. A transparent-PCS succinct proof whose verifier binds every layer, matrix
   root, activation transition, block field, nonce, difficulty target, and
   final activation digest, plus a verified link between the raw model bytes
   and proof commitment.
3. A reproducible, publicly reviewed model-generation ceremony, including its
   entropy sources, resulting artifact, and structural analyses.
4. Independent cryptographic and GPU-kernel implementations with matching test
   vectors.
5. Parser fuzzing, allocation/CPU caps, malformed-proof and resource-exhaustion
   tests on every network-facing verification path.
6. End-to-end resident and low-VRAM/streaming benchmarks, including the full
   winner proof, on named 16 GiB and representative lower-memory cards.
7. Audits by at least two teams that did not design the algorithm.
8. A public incentivized adversarial testnet covering output elision,
   partial-layer execution, sparse/zero inputs, transcript substitution,
   replay, proof malleability, target confusion, and CPU/GPU arithmetic
   divergence.

No production proof tag may be recognized by consensus until every gate above
is met. There must be no fallback that trusts miner-supplied activations,
digests, targets, model commitments, or partial-layer claims when proof
verification is unavailable or fails.

Devnet-0 now has bounded static-peer sessions, full block
validation before indexing, cumulative-chainwork fork choice and reorgs, a
checksummed append-only block log with consensus replay, touched-state atomic
active-chain validation, bounded bidirectional block synchronization, a bounded
volatile mempool with pull-based transaction propagation, and a bounded
CMFD-specific pool test protocol. Those features
make it a multi-node test harness; they do not make it safe for valuable funds.
Loopback/private addresses remain the default. An explicit
`--allow-public-peers` flag permits numeric public P2P addresses for bounded,
valueless testing, but does not add authentication, encryption, reputation,
automatic bans, NAT traversal, or DDoS resistance. RPC remains loopback-only,
`0.0.0.0` remains invalid, and operators should expose only TCP P2P port 18444.

Before any public-value or broadly advertised public testnet, the networking and storage design needs
explicit abuse, latency, and crash-recovery bounds. Peers are statically
configured and compatibility-checked by network ID and consensus fingerprint,
but are not identity-authenticated; P2P transport is unencrypted, with no peer
discovery, NAT traversal, reputation/ban system, or demonstrated DDoS
resilience. Extending a side branch currently reconstructs that branch from
genesis, which is deliberately Devnet-only and not scalable. The mempool is
volatile and intentionally excludes unconfirmed-parent packages. There is no
production wallet/key custody, durable pool payout system, or optimized GPU
miner.

New local Devnet data directories generate distinct Schnorr test keys and store
the raw 32-byte secret in `wallet.key`. The node does not return that secret
through RPC or desktop IPC. Existing nonempty Devnet-2 directories retain the
old source-visible demonstration key during migration so an upgrade cannot
strand their test outputs. The file is unencrypted: Unix creation requests mode
`0600`, while Windows relies on the containing data directory's ACLs. Stop the
node before backing it up and never distribute it. There is no password
encryption, mnemonic recovery, hardware-wallet integration, or independently
audited custody. These are valueless private-Devnet test tools, not production
wallets; never use either key mode for real value.

The native desktop wallet embeds the node and exposes only an explicit Tauri
command allowlist to its bundled webview. It does not open the loopback HTTP RPC
listener. The browser developer workflow still uses the loopback Vite proxy and
inherits the RPC limitations documented in the Devnet guide.

Continuous desktop mining uses the tiny full-recomputation Devnet profile. It
can optionally delegate the INT8 matrix stage to a CUDA library, but Rust fully
recomputes every below-target candidate before block submission or pool credit.
The performance counter is complete ForgeMatrix nonce evaluations, not raw GPU
TOPS or proof of physical VRAM residency. A missing or failed CUDA backend falls
back to the CPU evaluator and is reported in wallet status.

The Devnet pool is a CMFD-specific length-bounded job/share protocol over TLS
1.3; it is not Stratum. A client authenticates the server by comparing the
SHA-256 digest of the exact leaf-certificate DER bytes with the 64-hex pin in
its `cmfd+tls://...?...` URL. The TLS handshake still verifies that the pinned
certificate signed the handshake, but there is no CA trust path, client
certificate, worker identity proof, or automatic secure pin distribution.
Worker and payout claims are not client-authenticated, so session counters are
not identity-secure. Operators must transfer and verify the certificate pin out
of band and must never distribute the private key. The generator creates the
private-key DER with mode `0600` on Unix; Windows depends on the containing
directory's ACLs. Keep the certificate public, restrict both the key file and
pool data directory to the operator account, and distribute only the
certificate SHA-256 pin. Both client and server accept only numeric loopback,
RFC1918 IPv4, or IPv6 unique-local endpoints. TLS protects this one pool
connection; it does not encrypt or authenticate the separate P2P protocol.

The standalone miner's normal mode is a thin P2P client. A node supplies the
complete block template, including the payout-bound coinbase, and validates the
returned canonical block. The miner validates the Devnet network, configured
proof system, target bound, and CUDA result before submission, but it does not
independently maintain chain state. Treat templates as untrusted work and keep
the node's ordinary consensus validation on every submitted block. The legacy
`full-node` miner mode remains available for diagnostics only.

Each pool job binds its identifier to an immutable `BlockChallenge` and a
separate easier share target. Relation evaluation is deliberately targetless:
the server reconstructs the proof and work digest for the submitted nonce,
then compares that digest independently with the share target and the
challenge's chain target. A share target must be easier than or equal to the
chain target. It is never written into `BlockChallenge`, and a share-only proof
cannot construct a block. The server accepts a block only after the recomputed
proof meets the original chain target and ordinary block submission validates
it. Never accept a client-claimed digest or proof and never substitute a pool
share target for the committed chain target.

Pool resource and accounting state is intentionally bounded and in memory.
Duplicate nonces, stale jobs, low-difficulty shares, oversized frames, excess
connections, and configured record limits are rejected. Accepted-share,
rejected-share, block, and credited-atom values are session-only, valueless,
nonwithdrawable test counters that reset when the pool process restarts. The
client payout field is only an untrusted accounting label. The block's miner
reward output goes to the pool operator's configured destination; there is no
secure ownership mapping, crash-safe or reorganization-aware accounting,
withdrawal mechanism, or on-chain payout ledger. Payout labels remain
unauthenticated, so no displayed pool counter represents money owed to a
distinct user.

Production pool activation requires unique wallet and pool key custody,
persistent auditable and reorganization-aware share/reward accounting, an
on-chain payout mechanism, optimized GPU mining and proof generation,
share-verification queue and denial-of-service analysis, fuzzing and load
tests, independent implementations, and external audits. The Devnet TLS pool
must not be exposed to the public Internet or used with valuable funds.

A completed, sound proof can establish the committed function, not physical GPU
use or VRAM residency. No such hardware claim may be used to weaken the
arithmetic proof or any gate above.

Report vulnerabilities through GitHub's private advisory form:

<https://github.com/Common-Foundry-1/CommonFoundry/security/advisories/new>

Do not place working consensus bypasses, wallet exploits, private keys, or
mainnet exploit instructions in public issues. Include affected versions,
reproduction conditions, impact, and any proposed mitigation in the private
report.
