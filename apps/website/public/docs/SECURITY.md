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

Mainnet remains disabled until all of the following are complete:

1. A frozen production ForgeMatrix specification, a canonical bounded parser
   for the eventual production proof and public inputs, and concrete total
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

<https://github.com/JustAResearcher/CommonFoundry/security/advisories/new>

Do not place working consensus bypasses, wallet exploits, private keys, or
mainnet exploit instructions in public issues. Include affected versions,
reproduction conditions, impact, and any proposed mitigation in the private
report.
