# Verify the mainnet release before running it

The planned source and package publication time is October 2, 2026 at 17:00
UTC. Mining starts October 3 at 17:00 UTC. No final package is approved or
published by this document.

## Establish the release key first

The mainnet release checksum signer is `commonfoundry-mainnet-owner`, using an
Ed25519 key under the `commonfoundry-release` OpenSSH signature namespace. Its
approved public-key fingerprint is:

```text
SHA256:hhfV/4M5XDL2hLzeX0q/IMCR4fjSq5Kb8BjMC/Zj96Q
```

The source tree carries the corresponding public policy at
`packaging/mainnet/MAINNET-RELEASE.allowed_signers`. Its SHA-256 is
`49c382f071a5f04f12c86f98ce1f0d3a24c2cc14b3c294f19704220b254b3a7e`.
This policy is for release checksums; the separate
`MAINNET-PRODUCER.allowed_signers` policy uses a different namespace for plan
approval. Neither policy contains a private key.

Obtain and check the release-key fingerprint through an independently controlled
official project channel **before** trusting the download page. A key file,
fingerprint, or checksum supplied only beside the packages cannot by itself
authenticate that same package set. Publication of the independent fingerprint
and its exact location is a remaining launch gate. Stop if the independently
published fingerprint, this source policy, or the final release disagree.

## Verify the complete downloaded directory

Keep all files from the one `1.0.0` release together in a new directory,
including the four archives, `SHA256SUMS.txt`, `SHA256SUMS.txt.sig`, and the
release metadata. Use Python 3.11 or newer and the pinned dependencies in
`scripts/requirements-release-integrity.txt` from the published source. From
that source checkout, run one of these commands with an independently checked
copy of the release policy:

```powershell
py -3 scripts/release_integrity.py verify-download `
  --stage C:\path\to\complete-release-directory `
  --allowed-signers packaging/mainnet/MAINNET-RELEASE.allowed_signers `
  --signer-identity commonfoundry-mainnet-owner `
  --ssh-keygen C:\Windows\System32\OpenSSH\ssh-keygen.exe
```

```bash
python3 scripts/release_integrity.py verify-download \
  --stage /path/to/complete-release-directory \
  --allowed-signers packaging/mainnet/MAINNET-RELEASE.allowed_signers \
  --signer-identity commonfoundry-mainnet-owner \
  --ssh-keygen "$(command -v ssh-keygen)"
```

The verifier checks the detached signature under the release namespace before
trusting `SHA256SUMS.txt`, rejects missing or extra files, streams every asset
hash, and cross-checks build and source metadata. Its report names the exact
source commit and package version. Compare that commit with the announced
source release. Do not run a node, wallet, miner, installer, or update if any
check fails or if the trusted key identity cannot be established.

This command was exercised against the preserved, privately signed `a8b23ec`
candidate set on September 25. That candidate has since been superseded by
source changes and is not the final public release. Repeat the verification
against the exact published files at release time.
