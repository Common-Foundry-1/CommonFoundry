# Production key operations

This document defines the custody, rotation, and revocation controls required
for RCNet and mainnet. It does not assign owners or select launch keys. Those
values are approved separately and recorded in the production key register.

## Key register

Before RCNet-1, the release owner maintains an offline register with one row
per key or critical public-key policy:

| Required field | Meaning |
|---|---|
| Key ID | Stable human-readable identifier with no secret material |
| Purpose and environment | Release, reward, pool, ceremony, or infrastructure; RCNet or mainnet |
| Algorithm and public identity | Public key, destination, or certificate fingerprint |
| Primary and backup custodians | Named accountable operators |
| Approval threshold | Required independent approvals for use or rotation |
| Storage class | Hardware/offline, encrypted host store, or provider-managed secret |
| Backup custody | Number of sealed backups and independently controlled locations |
| Created and last verified | UTC timestamps and evidence reference |
| Rotation and revocation triggers | Planned lifetime and emergency conditions |
| Successor and retirement status | Current, overlapping, retired, or revoked |

The register contains no private key, seed phrase, passphrase, recovery code,
API token, or encrypted secret blob. A sanitized copy containing public
identities and policy may be published. Every change is reviewed by the
recorded threshold and preserved in the release evidence archive.

## Key classes

### Offline release signing key

- OpenSSH Ed25519 key used only with the
  `commonfoundry-release` signature namespace.
- Generated and used on an offline signing system outside source, build, and
  hosting checkouts.
- The public key and signer identity are distributed as the allowed-signers
  policy through more than one independently controlled channel.
- A release is public only after a second operator verifies its detached
  checksum signature and complete inventory.

### Steward and community destinations

- Consensus-fixed receive destinations selected before the network identity is
  frozen.
- Each destination must have documented beneficial ownership, custody,
  threshold, recovery, reporting, and permitted-use policy.
- The selected public destinations and their custody evidence are reviewed as
  launch inputs; private keys never enter the source tree or build system.
- Changing either destination changes consensus and requires an explicitly
  versioned network upgrade. It is not an ordinary wallet-key rotation.

### Pool wallet and payout custody

- The pool node wallet receives mined rewards and creates authenticated payout
  transactions.
- Its live key remains encrypted, its passphrase is supplied outside the
  command line, and its backup is stored separately from the passphrase.
- A pool operator cannot change custody while shares or payouts are
  unreconciled. The stopped ledger, wallet destination, balances, maturity,
  and pending transactions are recorded before and after a transition.

Miner payout keys belong to miners. The pool authenticates control through the
session challenge and never receives their private keys.

### Pool TLS key

- Authenticates the pool endpoint through the exact certificate SHA-256 pin in
  the miner URL.
- Stored with restrictive permissions and backed up only when the endpoint
  identity must survive host recovery.
- Rotation produces a new certificate pin and therefore a new miner URL. The
  new pin is announced through authenticated project channels before the old
  endpoint is retired.

### Ceremony and reproduction keys

- Identify independent artifact producers, reproducers, and evidence signers.
- Kept separate from release signing and reward custody so one role cannot
  attest its own independent result.
- Retained with the immutable generation/reproduction evidence.

### Hosting and infrastructure credentials

- GitHub, distribution, DNS, CDN, bootstrap-host, monitoring, and deployment
  credentials are non-consensus secrets with least-privilege scopes.
- Separate read, publish, DNS, and host-administration roles where the provider
  permits it.
- Rotate through the provider, verify the intended service, then revoke the
  prior credential. Provider tokens never sign release checksums.

## Baseline custody rules

1. Generate keys with an operating-system CSPRNG on the system appropriate to
   their storage class.
2. Never reuse a key across RCNet/mainnet or across release, reward, pool,
   ceremony, and infrastructure roles.
3. Keep private material out of source control, release archives, logs,
   screenshots, chat, shell history, and command-line arguments.
4. Require a second person to compare every public key, destination, or
   fingerprint from the original device to the approved register.
5. Test recovery with non-production funds or evidence before relying on a
   backup. Record only the public result and evidence hash.
6. Review access and backups at every release candidate and after personnel,
   device, provider, or policy changes.
7. Retired secrets remain protected until their signatures, funds, sessions,
   and rollback windows can no longer authorize an action.

## Planned release-key transition

A planned transition uses an overlap window so existing installations can
authenticate the successor policy.

1. Generate the successor offline and independently verify its public
   fingerprint.
2. Create a canonical transition record containing the signer identity, old
   and new public fingerprints, new public key, reason, UTC approval time,
   first release allowed to use the new key, overlap end, and approving
   custodians.
3. Sign the exact transition record with the current key under the namespace
   `commonfoundry-release-key-transition`.
4. Sign the same bytes with the successor key under the same namespace to
   prove custody before activation.
5. Verify both signatures on a disconnected verification host. Publish the
   record and signatures through every channel carrying the allowed-signers
   policy.
6. Ship at least one overlap release whose documentation carries both public
   identities. Existing clients continue to require their current trusted
   policy until they authenticate and install the successor policy.
7. After the overlap end, remove the old key from newly distributed policy,
   mark it retired in the register, and preserve the transition evidence.

The release archive remains immutable. A key transition never replaces a
previous binary or checksum file in place.

The repository includes a bounded create-new harness for the canonical record
and both signatures. The private keys remain offline and are never passed to
the Python process:

```text
python scripts/release-key-transition.py create \
  --signer-identity <release-identity> \
  --old-public-key <old-release-key.pub> \
  --new-public-key <new-release-key.pub> \
  --reason <approved-reason> \
  --approved-at-utc <YYYY-MM-DDTHH:MM:SSZ> \
  --first-release <version> \
  --overlap-ends-utc <YYYY-MM-DDTHH:MM:SSZ> \
  --approver <first-approver> --approver <second-approver> \
  --output <transition.json>

ssh-keygen -Y sign -f <old-private-key> \
  -n commonfoundry-release-key-transition <transition.json>
# Preserve the generated signature as old-key.sig before signing again.
ssh-keygen -Y sign -f <new-private-key> \
  -n commonfoundry-release-key-transition <transition.json>
# Preserve the second generated signature as new-key.sig.

python scripts/release-key-transition.py verify \
  --transition <transition.json> \
  --old-public-key <independently-trusted-old-release-key.pub> \
  --new-public-key <independently-checked-new-release-key.pub> \
  --old-signature <old-key.sig> \
  --new-signature <new-key.sig> \
  --output <create-new-verification-report.json>
```

The verifier requires canonical JSON, two distinct Ed25519 keys, at least two
unique approvers, a forward overlap window, exact public-key matches, and valid
old/new signatures under the dedicated namespace. It emits a create-new report
with the transition and signature hashes.

## Emergency release-key transition

If the current private release key may be exposed:

1. Stop release publication and mirror synchronization.
2. Record the last release independently verified before the exposure window.
3. Mark the key compromised in every independently controlled project channel
   and publish its fingerprint and cutoff time.
4. Activate a pre-approved offline recovery key or complete the governance
   threshold for a new trust root.
5. Publish the new allowed-signers policy and incident evidence through at
   least two independent channels. A signature from the compromised key alone
   is not sufficient to authenticate recovery.
6. Rebuild from the last trusted source commit on clean builders, compare
   reproducible outputs, sign with the recovered policy, and run the full
   update/rollback qualification before resuming publication.

This recovery depends on previously distributed governance and communication
channels; software cannot securely replace a compromised trust root by itself.

## Pool wallet transition

1. Stop the pool gracefully and preserve authenticated ledger and wallet
   backups.
2. Reconcile shares, mined blocks, maturity, credits, pending payouts, and
   on-chain balances under the old destination.
3. Create and recovery-test the successor encrypted wallet under independent
   custody. Record its public destination.
4. Settle or explicitly carry forward every old-ledger obligation before
   reopening share admission.
5. Transfer spendable residual funds with an ordinary signed transaction and
   record the transaction ID. Immature or otherwise locked outputs remain
   tracked under the old wallet until spendable.
6. Start the successor pool configuration, verify the displayed wallet
   destination and dashboard state, then issue a test share, block, and payout
   before broad miner admission.
7. Keep the old encrypted wallet and passphrase under separate recovery custody
   until every old obligation and rollback window is closed.

## Pool TLS transition

1. Gracefully stop the pool and back up its ledger.
2. Generate a new certificate/key pair with `pool-certificate`; do not
   overwrite the current pair.
3. Verify the printed SHA-256 pin on a second system and publish the complete
   new `cmfd+tls://` URL through authenticated channels.
4. Start a staged endpoint, connect a clean miner with the new pin, and confirm
   authenticated share credit.
5. Announce the cutoff, retire the old endpoint, revoke access to its private
   key, and preserve the public transition record.

## Fixed reward-destination transition

Steward and community destinations cannot be rotated by replacing a local
wallet file. A transition requires:

1. the approved governance and custody record for the successor destination;
2. an explicit consensus version and activation rule;
3. canonical vectors and network identity reflecting the new rule;
4. independent implementation/reproduction and external review;
5. signed release, update/rollback, and RCNet activation evidence; and
6. a public activation notice with both old and new destinations.

Mainnet launch should select durable threshold custody before freezing these
destinations so routine signer replacement can occur inside the custody system
without changing the on-chain destination.

## Required rehearsals and evidence

RCNet key operations are complete only after all of these use non-production
keys and preserve evidence:

- release signing, independent verification, planned dual-signature transition,
  new-policy verification, rollback, and old-key retirement;
- encrypted wallet backup, recovery on a fresh host, destination comparison,
  and relock;
- pool wallet stop/reconcile/recovery/test-payout exercise;
- pool TLS pin rotation and clean-miner reconnection; and
- one infrastructure credential rotation with old-credential revocation.

The final mainnet register additionally requires the real custodians, approval
thresholds, public identities, backup attestations, review date, and emergency
contacts. Those operator decisions cannot be satisfied by a source-code
change.
