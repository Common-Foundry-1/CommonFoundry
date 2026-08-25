# Production RC release gate

Production release-candidate labels are fail-closed. A build is treated as a
production RC when `cmfd-node` is built with the `production-rc` feature, when
`CMFD_RELEASE_LABEL` names a production/mainnet RC, when the package version is
a non-Devnet RC, or when GitHub builds a matching production-RC ref. Devnet and
testnet RC labels are deliberately excluded.

The build proceeds only when the source-selected profile is RCNet, its consensus
proof selector is `ProductionV3`, and the compiled profile contains complete
activation evidence: the qualification source commit, qualification-manifest
SHA-256, fresh-process verifier binary SHA-256, and fresh-process verifier report
SHA-256. A production build must also receive the exact release checkout as
the trusted `CMFD_BUILD_SOURCE_COMMIT` input. It must also pin the exact byte
length, BLAKE3 digest, and SHA-256 digest of the production bank, manifest, and
Record V2. The current source selection is Devnet/V2 with no activation
evidence, artifact pins, or final production-network identity pin, so this
command must fail:

```text
cargo check --locked -p cmfd-node --features production-rc
```

Release finalization applies a second, artifact-level check. Any production-RC
stage must inventory `NETWORK-INFO.json`, `RCNET-LAUNCH-CANDIDATE.json`,
`PRODUCTION-V3-ACTIVATION.json`, the actual
`PRODUCTION-V3-QUALIFICATION-MANIFEST.json`, the exact
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER.bin`, and its
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER-REPORT.json`. The compiled manifest must
identify RCNet-1, select `ProductionV3`, bind the checked-out release commit
provided by the trusted build job, and bind the exact activation-evidence bytes
by SHA-256.

`cmfd-node rcnet-candidate` creates the launch-candidate file without
overwriting an existing path. It accepts the canonical final Record V2 and
explicit timestamp, bootstrap, port, proof-of-work limit, and reward
destinations. Its launch root binds those values, every compiled consensus and
economic parameter, and the Record V2/model identities. The network ID and
virtual genesis are independently derived from that root under distinct
BLAKE3 domains; neither derived value is an input to the root.

The finalizer recomputes SHA-256 over the staged qualification manifest,
fresh-process verifier binary, and fresh-process verifier report and requires
exact matches in the activation evidence. It also checks that the qualification
manifest binds the staged verifier artifacts, the pinned Cargo and rustc
binaries, the generated Cargo configuration, production n=33/134-claim
geometry, an RCNet-1 qualification identity, and a successful fresh-process
same-build verifier report. This is process isolation, not an independently
built verifier claim. Arbitrary well-formed nonzero digest strings cannot pass.
These files then become ordinary hashed release artifacts in `BUILDINFO.json`
and `SHA256SUMS.txt`.

Both build and finalization gates reject zero or repeated-byte network/genesis
identities, RFC 5737 documentation bootstraps, and the known deterministic
Devnet reward keys. Finalization additionally requires the compiled network
manifest to match the candidate's identity, timestamp, services, difficulty
limit, rewards, and Record V2 identity. The current RCNet constants remain
placeholders and therefore cannot pass these checks.

For the binary-only RC, finalization also pins the service allocation to RPC
`19443`, P2P `19444`, and pool `19445`; rejects source-like top-level release
assets; and requires the wallet JavaScript package, Tauri package/config, node,
miner, and proof-worker manifests that produce shipped applications to carry
the exact same non-Devnet RC version supplied to the finalizer. Internal
library crates retain independent semantic versions. Runtime policy keeps RPC
loopback-only. Release launchers and firewall instructions must expose only TCP
`19444`; they must not start or expose the pool service on `19445`.

These checks do not sign binaries or `SHA256SUMS.txt`, generate an SBOM, inspect
the contents of GitHub's automatically generated source archives, or distribute
the multi-gigabyte model bank. Those are separate release gates. A public
binary repository must contain only reviewed binary-release metadata, and the
model bank must be delivered through a create-new partial download that checks
the compiled byte length, BLAKE3, and SHA-256 pins before atomic publication.
The node then authenticates the bank, manifest, and Record V2 again before
opening chain storage.

The qualification manifest records the older exact commit used to build and
run the qualifying verifier. The final activation evidence separately records
the release checkout commit supplied as trusted CI input. This avoids the
impossible requirement for a committed source constant to contain its own
future commit hash; the release finalizer matches the dynamic build identity to
the checked-out commit.

Changing a label, branch name, archive name, or package name cannot satisfy
these checks. Activation requires the real profile/proof integration and the
committed qualification evidence; no override or fallback flag exists.
