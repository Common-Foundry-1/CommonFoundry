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
evidence or artifact pins, so this command must fail:

```text
cargo check --locked -p cmfd-node --features production-rc
```

Release finalization applies a second, artifact-level check. Any production-RC
stage must inventory `NETWORK-INFO.json`, `PRODUCTION-V3-ACTIVATION.json`, the
actual `PRODUCTION-V3-QUALIFICATION-MANIFEST.json`, the exact
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER.bin`, and its
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER-REPORT.json`. The compiled manifest must
identify RCNet-1, select `ProductionV3`, bind the checked-out release commit
provided by the trusted build job, and bind the exact activation-evidence bytes
by SHA-256.

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

The qualification manifest records the older exact commit used to build and
run the qualifying verifier. The final activation evidence separately records
the release checkout commit supplied as trusted CI input. This avoids the
impossible requirement for a committed source constant to contain its own
future commit hash; the release finalizer matches the dynamic build identity to
the checked-out commit.

Changing a label, branch name, archive name, or package name cannot satisfy
these checks. Activation requires the real profile/proof integration and the
committed qualification evidence; no override or fallback flag exists.
