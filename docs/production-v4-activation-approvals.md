# ProductionV4 activation approval contract

This document defines the signed approval boundary for the two-phase
ProductionV4 RCNet-1 activation. It does not designate real signers or approve
activation. The tracked activation pin remains `None` until the process below
is completed with independently controlled keys and explicitly trusted
allowed-signers authorities.

## Required roles

Every phase requires exactly two approvals:

| Role | Approval role value | OpenSSH signature namespace |
|---|---|---|
| Original producer | `producer` | `commonfoundry-production-v4-activation-producer-v1` |
| Independent reproducer | `independent_reproducer` | `commonfoundry-production-v4-activation-independent-reproducer-v1` |

The signer identities must differ and the allowed public-key blobs must differ.
The contract rejects a role-swapped signature because both the signed payload
and the OpenSSH namespace are role-specific. This proves use of two distinct
trusted keys; the project must still establish and record that the reproducer
is organizationally and operationally independent of the producer.

No signer identity, public key, signature, or approval timestamp is supplied by
the repository. Those are real operator inputs, not software-generated
evidence.

## Dedicated trust authorities

Each role uses a separate, single-entry OpenSSH allowed-signers file. Its exact
ASCII encoding is:

```text
<identity> namespaces="<exact-role-namespace>" <public-key-type> <base64-public-key-blob>
```

The file is LF-terminated and contains no comment, extra principal, wildcard,
certificate authority, second key, or additional option. The verifier rejects
symbolic links and records the SHA-256 of the complete authority file, the key
blob, its OpenSSH-style SHA-256 fingerprint, and its key type. The two
authorities, identities, and key blobs must all be distinct.

The `pin` phase places those exact trust descriptors in the reviewed Rust
source pin. The `evidence` phase and final RC release validation must match the
compiled descriptors, so replacing an allowed-signers file and supplying a
matching attacker-controlled signature cannot satisfy the gate.

## Canonical signed payload

Each detached OpenSSH signature covers the complete canonical UTF-8 JSON bytes
of one `CMFD_PRODUCTION_V4_ACTIVATION_ROLE_APPROVAL_V1` object. The object
contains:

- its exact role, namespace, signer identity, and trusted-authority descriptor;
- a `CMFD_PRODUCTION_V4_ACTIVATION_APPROVAL_SUBJECT_V1` subject;
- the phase (`pin` or `evidence`);
- the activation, artifact-generation, and qualification source commits;
- the reviewed activation source-pin SHA-256;
- RCNet-1 profile, launch root, network ID, virtual-genesis hash and timestamp,
  and proof-of-work limit;
- byte length, SHA-256, and BLAKE3 identity for the launch candidate, RCNet input
  manifest, proof template, proof, model bank, fixed record, all twelve fixed-bank
  artifacts, independent reproduction report, fresh-process verifier report,
  and exact verifier script; and
- for the `evidence` phase, the intended canonical activation-evidence bytes
  and compiled `NETWORK-INFO.json` bytes.

There are no optional or extension fields. Duplicate JSON keys, noncanonical
JSON, missing detached signatures, unknown file roles, and phase changes are
rejected. Signing a `pin` payload cannot authorize `evidence`; both roles must
review and sign a newly derived payload after the pin-only activation commit
exists.

## Verification behavior

`scripts/production_v4_activation_approval.py` derives the expected payloads
from already validated release inputs. It does not trust identity or hash
claims read from an approval JSON file. The supplied JSON must be byte-for-byte
equal to the derived canonical payload before OpenSSH is invoked.

The verifier snapshots regular non-symlink inputs, copies the exact trusted
`ssh-keygen`, allowed-signers files, and signatures to a private temporary
directory, verifies the role payload bytes with `ssh-keygen -Y verify`, and
then confirms that every original file is unchanged. Its receipt records both
approval and signature hashes but is not itself activation authority.

The expected SHA-256 of `ssh-keygen` is an explicit operator input and is
embedded in the reviewed source pin. Obtain and review that digest through a
trusted channel before preparing either approval round. The copied verifier
runs with a minimal environment: private home and temporary directories, no
inherited loader, OpenSSL-provider, security-key-provider, or Python variables,
and no inherited `PATH`. On Windows only the original verifier directory and
`System32` are placed in a constructed `PATH`, and `ProgramData` is derived
from the Windows system root. Windows OpenSSH still dynamically loads its
operating-system libraries, including its installed `libcrypto.dll`; the
release host ACL and clean-host qualification therefore remain part of the
trusted verifier boundary.

## Command flow

First derive the exact payloads. Replace every uppercase placeholder with a
reviewed absolute path or real signer identity. `--network-info` is omitted for
the `pin` phase and is mandatory for the `evidence` phase.

```text
python scripts/release_integrity.py production-v4-approval-request \
  --repo REPOSITORY --expected-commit FULL_COMMIT --phase pin \
  --candidate RCNET-LAUNCH-CANDIDATE.json \
  --input-manifest production-v4-rcnet-1-inputs.json \
  --qualification-manifest PRODUCTION-V4-QUALIFICATION-MANIFEST.json \
  --verifier-report PRODUCTION-V4-FRESH-PROCESS-VERIFIER-REPORT.json \
  --verifier-script PRODUCTION-V4-FRESH-PROCESS-VERIFIER.py \
  --template PRODUCTION_V4_TEMPLATE --proof QUALIFICATION_PROOF \
  --model-bank MODEL-V2.bank \
  --fixed-record FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
  --artifact-directory FIXED_ARTIFACT_DIRECTORY \
  --producer-allowed-signers PRODUCER_ALLOWED_SIGNERS \
  --producer-signer-identity PRODUCER_IDENTITY \
  --reproducer-allowed-signers REPRODUCER_ALLOWED_SIGNERS \
  --reproducer-signer-identity REPRODUCER_IDENTITY \
  --ssh-keygen TRUSTED_SSH_KEYGEN \
  --expected-ssh-keygen-sha256 REVIEWED_SSH_KEYGEN_SHA256 \
  --output-directory EMPTY_CREATE_NEW_DIRECTORY
```

The command writes only the two canonical role payloads and the proposed
`PIN-TARGET.review`; it never writes the tracked include. Each key holder signs
only the payload for that holder's role:

```text
ssh-keygen -Y sign -f PRODUCER_PRIVATE_KEY \
  -n commonfoundry-production-v4-activation-producer-v1 \
  PRODUCTION-V4-ACTIVATION-PIN-PRODUCER-APPROVAL.json

ssh-keygen -Y sign -f REPRODUCER_PRIVATE_KEY \
  -n commonfoundry-production-v4-activation-independent-reproducer-v1 \
  PRODUCTION-V4-ACTIVATION-PIN-REPRODUCER-APPROVAL.json
```

Run `production-v4-activation` with the same validated inputs and trust flags,
plus the two payload and detached-signature paths. It re-derives the bytes,
verifies both signatures, rechecks the clean source history, and writes the
requested review output with create-new semantics. For the pin phase the output
must be outside the tracked include; an operator reviews it before the sole
`None`-to-pin commit. For the evidence phase use `--phase evidence`, supply
`--network-info NETWORK-INFO.json`, and name `--output` exactly
`PRODUCTION-V4-ACTIVATION.json`.

```text
python scripts/release_integrity.py production-v4-activation \
  --repo REPOSITORY --expected-commit FULL_COMMIT --phase pin \
  --candidate RCNET-LAUNCH-CANDIDATE.json \
  --input-manifest production-v4-rcnet-1-inputs.json \
  --qualification-manifest PRODUCTION-V4-QUALIFICATION-MANIFEST.json \
  --verifier-report PRODUCTION-V4-FRESH-PROCESS-VERIFIER-REPORT.json \
  --verifier-script PRODUCTION-V4-FRESH-PROCESS-VERIFIER.py \
  --template PRODUCTION_V4_TEMPLATE --proof QUALIFICATION_PROOF \
  --model-bank MODEL-V2.bank \
  --fixed-record FORGEMATRIX-V4-FIXED-ARTIFACT-RECORD-V1.json \
  --artifact-directory FIXED_ARTIFACT_DIRECTORY \
  --producer-allowed-signers PRODUCER_ALLOWED_SIGNERS \
  --producer-signer-identity PRODUCER_IDENTITY \
  --producer-approval PRODUCTION-V4-ACTIVATION-PIN-PRODUCER-APPROVAL.json \
  --producer-signature PRODUCTION-V4-ACTIVATION-PIN-PRODUCER-APPROVAL.json.sig \
  --reproducer-allowed-signers REPRODUCER_ALLOWED_SIGNERS \
  --reproducer-signer-identity REPRODUCER_IDENTITY \
  --reproducer-approval PRODUCTION-V4-ACTIVATION-PIN-REPRODUCER-APPROVAL.json \
  --reproducer-signature PRODUCTION-V4-ACTIVATION-PIN-REPRODUCER-APPROVAL.json.sig \
  --ssh-keygen TRUSTED_SSH_KEYGEN \
  --expected-ssh-keygen-sha256 REVIEWED_SSH_KEYGEN_SHA256 \
  --output REVIEWED_PIN_OUTPUT
```

The evidence request produces correspondingly named `EVIDENCE` payloads. Stage
the verified evidence payloads and signatures under these canonical final
names:

| Evidence request artifact | Final stage name |
|---|---|
| `PRODUCTION-V4-ACTIVATION-EVIDENCE-PRODUCER-APPROVAL.json` | `PRODUCTION-V4-ACTIVATION-PRODUCER-APPROVAL.json` |
| its detached `.json.sig` | `PRODUCTION-V4-ACTIVATION-PRODUCER-APPROVAL.json.sig` |
| producer authority | `PRODUCTION-V4-ACTIVATION-PRODUCER.allowed_signers` |
| `PRODUCTION-V4-ACTIVATION-EVIDENCE-REPRODUCER-APPROVAL.json` | `PRODUCTION-V4-ACTIVATION-REPRODUCER-APPROVAL.json` |
| its detached `.json.sig` | `PRODUCTION-V4-ACTIVATION-REPRODUCER-APPROVAL.json.sig` |
| reproducer authority | `PRODUCTION-V4-ACTIVATION-REPRODUCER.allowed_signers` |

Finalization and source-backed verification require the same independently
reviewed verifier digest:

```text
python scripts/release_integrity.py finalize \
  --repo REPOSITORY --expected-commit FULL_COMMIT --version PRODUCTION_RC_VERSION \
  --stage RELEASE_STAGE --inventory TRACKED_INVENTORY \
  --activation-ssh-keygen TRUSTED_SSH_KEYGEN \
  --activation-ssh-keygen-sha256 REVIEWED_SSH_KEYGEN_SHA256
```

The final gate re-renders the source pin from staged evidence and trust,
requires byte equality with the tracked pin, proves the exact pin-only Git
transition, reconstructs the signed subject from independently validated stage
artifacts, and re-verifies both signatures. Missing approval files, a changed
authority, a different verifier, an unsigned payload, or an approval whose
common-file binding does not match the compiled pin keeps the RC closed.

## Two-phase operating sequence

1. Select the real producer and organizationally independent reproducer. Keep
   their private keys outside the repository, build host, seed host, release
   staging, and approval exchange channel.
2. Create one dedicated allowed-signers authority per role. Review and preserve
   those exact files through a trusted out-of-band channel.
3. From a clean qualification checkout, derive the two canonical `pin` approval
   payloads. Each role reviews the complete subject and signs only its own
   payload with its exact namespace.
4. Verify both signatures and authority descriptors. Render the proposed Rust
   source pin to a separate create-new file. Review it before making the sole
   `None`-to-pin source change and commit that change by itself.
5. Build the pinned source commit and capture canonical `NETWORK-INFO.json`.
   Derive new `evidence` approval payloads bound to that commit and the intended
   activation evidence. Both roles independently review and sign again.
6. Verify the evidence-phase signatures against the trust descriptors compiled
   by step 4, then create the activation evidence. The final RC release gate
   re-verifies the staged payloads, signatures, authorities, network identity,
   reports, artifacts, and runtime packages.

At no point does the tool write the tracked activation include. Existing
outputs are never overwritten. Until both real approval rounds and the other
RC qualification gates complete, a production RC remains blocked.
