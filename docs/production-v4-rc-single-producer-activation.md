# ProductionV4 RC single-producer activation

RCNet-1 may be activated by one project producer after the source commit is
frozen and the preserved block-1 proof passes the full independent verifier.
This policy is deliberately limited to an experimental release candidate. It
does not claim independent reproduction, an external audit, or mainnet
authorization. Mainnet now has its own explicitly owner-signed policy;
see [mainnet plan approvals](mainnet-plan-approvals.md). This RC signature alone
still cannot authorize mainnet.

The preparation command refuses a dirty source tree, an existing activation
pin, a mismatched RCNet candidate, mismatched model or fixed-record artifacts,
or a proof that fails the strict-statement cryptographic verifier. It creates a
canonical approval bundle outside the repository. The producer reviews and
signs only `RCNET1-PRODUCER-ACTIVATION-APPROVAL.json` with the dedicated RC
activation key and namespace.

```powershell
python scripts/production-v4-rc-single-producer.py prepare `
  --repo D:\CommonFoundry-RC1\sub20-proof `
  --candidate D:\CommonFoundry-RC1\artifacts\RCNET1-LAUNCH-CANDIDATE-V2.json `
  --template D:\CommonFoundry-RC1\qualification\rcnet1-block1-proof-361f182-r4\RCNET1-BLOCK1-CANDIDATE-927.json `
  --proof D:\CommonFoundry-RC1\qualification\rcnet1-block1-proof-361f182-r4\RCNET1-BLOCK1-TRANSPARENT-PROOF-927-WSL-NATIVE.bin `
  --proof-log D:\CommonFoundry-RC1\qualification\rcnet1-block1-proof-361f182-r4\proof-wsl-native.log `
  --model-bank D:\CommonFoundry-RC1\artifacts\RCNET1-MODEL-V2.bank `
  --fixed-record D:\CommonFoundry-RC1\sub20-v4-fixed-artifacts\FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json `
  --allowed-signers D:\CommonFoundry-RC1\signing\rcnet1-producer-activation\PRODUCTION-V4-ACTIVATION-PRODUCER.allowed_signers `
  --signer-identity 030manager@gmail.com `
  --ssh-keygen C:\Windows\System32\OpenSSH\ssh-keygen.exe `
  --output-directory D:\CommonFoundry-RC1\signing\rcnet1-activation-approval
```

After signing, `verify --install-pin` verifies the exact approval bytes, signer
authority, namespace, frozen commit, bundle identities, and proposed pin before
writing the tracked include. The resulting source change must be committed as a
pin-only commit and tested with the `production-rc` feature before packaging.
