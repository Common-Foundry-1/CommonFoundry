# Production RC release gate

Production release-candidate labels are fail-closed. A build is treated as a
production RC when `cmfd-node` is built with the `production-rc` feature, when
`CMFD_RELEASE_LABEL` names a production/mainnet RC, when the package version is
a non-Devnet RC, or when GitHub builds a matching production-RC ref. Devnet and
testnet RC labels are deliberately excluded.

The build proceeds only when the source-selected profile is RCNet, its consensus
proof selector is `ProductionV3`, and the compiled profile contains complete
activation evidence: the activating source commit, the qualification-manifest
SHA-256, and an independent-verifier SHA-256. The current source selection is
Devnet/V2 with no activation evidence, so this command must fail:

```text
cargo check --locked -p cmfd-node --features production-rc
```

Release finalization applies a second, artifact-level check. Any production-RC
stage must inventory both `NETWORK-INFO.json`, emitted by the compiled node, and
`PRODUCTION-V3-ACTIVATION.json`. The compiled manifest must identify RCNet-1,
select `ProductionV3`, and bind the exact activation-evidence bytes by SHA-256.
The evidence must bind the release commit and contain nonzero qualification and
independent-verifier digests. Both files then become ordinary hashed release
artifacts in `BUILDINFO.json` and `SHA256SUMS.txt`.

Changing a label, branch name, archive name, or package name cannot satisfy
these checks. Activation requires the real profile/proof integration and the
committed qualification evidence; no override or fallback flag exists.
