---
name: cmfd-verify-release
description: Verify signed Common Foundry (CMFD) desktop, node, or miner release packages before installation or updates. Use when downloading CMFD mainnet software, checking checksums or release signatures, or diagnosing a failed package verification.
---

# Verify a Common Foundry release

1. Resolve the intended mainnet desktop/node/miner release from the [full release list](https://github.com/Common-Foundry-1/CommonFoundry/releases). `releases/latest` can select an Android release. Exclude prereleases, research artifacts, and previews unless the user specifically requested them. Record the tag, source commit, operating system, and architecture.
2. Read that tag's `docs/mainnet-release-verification.md`, `packaging/mainnet/USER-GUIDE.md`, and asset list. Use the verification script and pinned requirements from the matching source commit. Requirements and asset counts can change; do not substitute files from another release.
3. Establish the release signer separately from the downloaded archives using [the public key policy](https://commonfoundry.ai/mainnet-release-key.txt) and the release's `packaging/mainnet/MAINNET-RELEASE.allowed_signers`. The published mainnet checksum identity is `commonfoundry-mainnet-owner` in the `commonfoundry-release` SSH signature namespace. The current published fingerprint is `SHA256:cA1Tsf8hL/pxDV5WpOE3iPW3b4uDQosu1dOh//4a/fk`. A changed key requires independently established rotation evidence; a key bundled beside an archive cannot authenticate that archive by itself.
4. Download the complete asset set from that single release into a new staging directory, including `SHA256SUMS.txt`, its `.sig`, and release metadata. The verifier rejects missing and extra files. Keep existing installations and wallet data outside this directory.
5. From the matching source checkout, run the documented verifier with Python 3.11 or newer, its pinned dependencies, an independently checked signer policy, and OpenSSH `ssh-keygen`. For example on Windows, replacing only the staging path:

```powershell
py -3 scripts/release_integrity.py verify-download `
  --stage C:\path\to\complete-release-directory `
  --allowed-signers packaging/mainnet/MAINNET-RELEASE.allowed_signers `
  --signer-identity commonfoundry-mainnet-owner `
  --ssh-keygen C:\Windows\System32\OpenSSH\ssh-keygen.exe
```

On Linux, use `python3`, a Linux staging path, and `--ssh-keygen "$(command -v ssh-keygen)"` with the same arguments. Follow the selected release if its procedure differs.

Report the verified tag, source commit, signer fingerprint, asset checks, and verifier result. A checksum match without a trusted signature is incomplete. Stop installation on a signature, identity, hash, or source mismatch; retain the failing report. Successful package verification establishes provenance and integrity, not hardware qualification, an independent security audit, or profitable mining.
