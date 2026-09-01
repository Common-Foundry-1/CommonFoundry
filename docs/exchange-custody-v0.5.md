# Exchange custody v0.5

Status: implemented as an explicit, opt-in custody candidate. It does not
silently upgrade the v0.4 preview and it is not a production-custody claim.
The keyring can route inputs to encrypted local keys or authenticated external
signer identities, including a remote HSM or a threshold service represented
by its aggregate BIP340 public key. No specific HSM vendor, remote transport,
or threshold implementation is certified by this repository.

## What v0.5 changes

The v3 path adds the operational controls that v0.4 deliberately lacked:

- an authenticated encrypted keyring with an independently stored rollback
  anchor, local or external signer bindings, an exact plan/apply import from
  the legacy wallet key, and a narrowly scoped create-new transition from that
  imported single local key to an active external signer key;
- an explicit, offline v2-to-v3 journal migration that retains both v2 slots
  and the legacy marker before publishing a v3 activation marker;
- action-separated `release` and `cancel` approvals, each checked against its
  own sorted Schnorr approver roster and threshold;
- policy limits for one amount, one fee, one debit, rolling 24-hour debit, and
  rolling 24-hour release count, with signed authorization time retained as
  evidence and durable local submission time used for rolling accounting;
- durable `Intent`, `Prepared`, `ReleaseAuthorized`, `Released`, and
  `Canceled` phases;
- an atomic runtime that persists authorization before signing, persists exact
  signed transaction bytes before broadcast, and restores reservations before
  replay after restart;
- native wallet signing and submission exclusion while v3 owns the wallet,
  including manual send, consolidation, and pool-payout paths, while unrelated
  third-party transaction relay remains available; a persisted v3 activation
  marker or detected v3 slot keeps that exclusion and the hardened legacy-wallet
  passphrase boundary latched across a restart that omits v3 flags;
- authenticated archive, independently stored manifest pin, offline restore
  verification, and explicit compaction for `Canceled` records only; and
- retained-handle file checks, symlink/reparse-point rejection, Unix effective
  identity and ancestor-directory checks, and Windows file-plus-complete-
  ancestor-chain ACL validation for the v3 runtime's journal/keyring files and
  external control material.

The RPC credential routes a request but never approves it. A valid threshold
approval bound to the exact policy, action, request, signing digest, and
Prepared journal anchor is required to release or cancel. Initial policy and
keyring provisioning, migration, archive, and compaction are offline operator
operations and are not RPC methods. v0.5 implements only the explicit
single-imported-key to mixed external migration stage and the guarded
mixed-to-external-only finalization documented below; it has no general
keyring, policy, or journal-key rotation command. Do not replace bound inputs
in place; any later rotation requires a separately designed, reviewed, and
qualified migration.

## Durable transition order

The release path has one permitted order:

1. Validate the request and wallet inputs, construct the exact unsigned
   transaction and signer package, and publish one atomic `Prepared` candidate.
2. The exchange coordinator independently persists the returned Prepared
   anchor.
3. Approvers sign a `release` document for that exact anchor and transaction
   signing digest.
4. The node verifies policy, threshold, the maximum 15-minute validity
   interval, and rolling limits at durable local submission time, then
   publishes `ReleaseAuthorized`. Input
   reservations and the policy charge remain active.
5. The node returns without signing. The coordinator independently persists
   the returned `ReleaseAuthorized` anchor.
6. The exchange retries `releasewithdrawal` with the exact same request and
   canonical approval payload. Local inputs are signed in process. For any
   external inputs, the exchange first obtains the exact authorized package
   with `getwithdrawalsigningpackage`, obtains one canonical response from
   each referenced external signer, and supplies those responses as the third
   parameter. A completion-only engine requires the externally pinned
   `ReleaseAuthorized` anchor, reconstructs and revalidates the exact plan,
   verifies every returned transaction and package-authorization signature,
   and durably publishes the exact `Released` transaction bytes.
7. Only after step 6 succeeds may the node submit those bytes to the mempool.
8. The coordinator persists the returned Released anchor.

`ReleaseAuthorized` is a mandatory external pinning boundary. The first
release call consumes policy budget and returns that durable phase without
using a transaction key. If the process stops there, restart restores the
reservation and consumed policy budget. After the coordinator pins that exact
anchor, the same release request can complete or replay only its exact
transaction. Expiry is consumed before durable authorization and does not
strand an already authorized recovery.

Cancellation follows a separate path. Approvers sign a `cancel` document for
the exact current action anchor. The node durably publishes `Canceled` before
removing reservations, and the coordinator then pins the returned Canceled
anchor. A release approval cannot cancel, a cancel approval cannot release,
and a `ReleaseAuthorized` request can no longer be canceled.

## Files and authority separation

Use separate protected locations and service identities where possible:

| Material | Writer | Node access | Purpose |
|---|---|---|---|
| v3 journal slots and marker | node | read/write | authenticated live state |
| journal key | provisioning operator, then service-owned handoff | read only in normal operation | keyed journal authentication |
| external journal anchor | exchange coordinator | read only | rollback detection and mutation gate |
| policy document | policy operator | read only | limits and approval rosters |
| encrypted keyring | provisioning operator | read in normal operation | local secrets and/or external signer bindings |
| keyring anchor | exchange coordinator | read only | keyring rollback detection |
| wallet/keyring passphrase files | secret provisioner or external-secret authority, by stage | read once by the consuming command | decrypt local keys |
| integration/withdrawal RPC auth files | credential provisioner, then external-secret authority | read once at startup | route requests; never approve custody actions |
| signed approvals | approvers/exchange service | supplied per RPC call | authorize one terminal action |
| archive | archive operator | offline only | retain exact canceled-record history |
| manifest pin | independent archive/control authority | read only during apply/verify | prove the exact retained archive |

The external journal anchor, policy, keyring anchor, archive pin, passphrase
files consumed by migration, archive, or runtime, both v3 RPC authentication
files, and any retained approval files must be outside the node data directory.
The node never updates an external anchor. The encrypted keyring may be
node-owned, but its independently controlled keyring anchor must remain outside
the node's rollback authority.

The journal key is a node secret, not an independent authorization control.
After offline generation and backup, install its exact bytes in a separate
service-owned, owner-only path outside the data directory. The service may read
but must not rewrite it during normal operation. Do not place it under an
operator/anchor directory whose ownership or parent ACL conflicts with the
node-secret profile.

On Unix, run v3 as a dedicated non-root service identity. Whenever the relevant
runtime or offline command consumes one, that identity must not own or have
effective write access to the external journal anchor, policy, keyring anchor,
validated migration snapshot, or independent archive manifest pin, and it must
not own or have effective write access to any directory above those files.
Wallet and keyring passphrase files consumed by migration, archive, or runtime,
and both v3 RPC authentication files, follow the confidential external-secret
variant of the same rule: a dedicated group may grant read access, but
other-user access and all group/other write access are rejected. Mode bits on
the file alone are not an authority boundary because an owner can change them
and a writable ancestor permits replacement. The production external-control
loader checks the opened file identity and the complete resolved ancestor chain
and fails closed when this separation is absent. A root process cannot satisfy
this on-host independence contract. Keyring-import plan/apply passphrases are
instead provisioner-owned protected inputs. Before migration planning, archive
work, or runtime, transfer the wallet and keyring passphrase files to the
independent external-secret paths and authority; those paths do not accept a
node/provisioner-writable substitute.

The node-owned activation marker or a detected v3-format journal slot prevents
an ordinary omitted-flag restart from reopening native wallet mutation and
keeps the wallet-passphrase load on the hardened external-secret path. It is
not an independent boundary against an identity that can delete or roll back
the node data directory. `exchange_custody_v3_wallet_state` is present in
`cmfd-node status` output and the startup document's nested `status`:
`unclaimed` permits native wallet mutation, `required` means persisted
v3 state has latched it closed but the runtime is not active, and `active` means
the v3 runtime owns it. Native wallet mutations in either locked state fail
with `exchange_custody_v3_wallet_exclusive`. Production service configuration
must require the complete v3 flag set, treat any expected-custody startup value
other than `active` or absence of top-level `"exchange_rpc_custody":"v3"` as a
deployment failure, and protect that configuration outside the node identity's
write authority.

On Windows, provision dedicated directories whose DACLs grant only the
intended service and coordinator identities. Merely marking a file read-only
is insufficient when the node can replace it through its parent directory.
The runtime validates the file and complete ancestor chain, rejecting broad or
unverifiable mutation authority; it is not a boundary against an
Administrator, LocalSystem, take-ownership, or restore-privilege compromise.
The packaged-host qualifier adds an exact per-material SID allowlist: every
security-relevant owner/allow ACE must resolve to the fixed service,
operator/anchor, or an explicitly configured additional OS authority. SYSTEM,
Administrators, and TrustedInstaller are not implicit exceptions.

On Linux, the qualifier resolves the fixed identities to explicit UID
authorities and any required dedicated groups to explicit GID authorities. It
rejects a configured group containing any unrelated primary or supplementary
member, every unlisted owner or group writer in the full replacement-relevant
ancestor chain (including the data-directory chain), and every extended POSIX
access/default ACL. Root-owned system ancestors are recorded as the privileged
`uid:0` OS boundary rather than treated as an implicit custody role. The actual
service process must have matching real/effective/saved/filesystem UIDs,
matching real/effective/saved/filesystem GIDs, and no inheritable, permitted,
effective, or ambient Linux capabilities.

Before starting the deployed service, run the packaged-host qualifier described
in [Exchange custody packaged-host ACL qualification](exchange-custody-acl-qualification.md).
Only `result: "host_qualified"` from `qualification_scope: "installed_host"`
under the actual service identity is host evidence. A passing dry fixture is a
parser/policy test and deliberately sets `host_qualified: false`.

Run commands under the identity whose authority the command is meant to prove.
External-control validation evaluates the current process token, not a future
service token. On Unix, do not run these validation steps as `root`; on Windows,
do not use an elevated Administrator token as the custody service identity.

| Stage | Execution identity | Required handoff or boundary |
|---|---|---|
| keyring import plan/apply | restricted offline provisioning identity | Create the encrypted keyring in node-owned storage. Create its anchor in a staging path, then transfer the exact bytes to the independently controlled keyring-anchor path and remove node/provisioner write authority before migration or runtime. |
| imported-keyring external transition plan/apply | restricted offline provisioning identity, before the source anchor is handed off | Retain the imported source envelope and anchor, create a generation-2 candidate with the old local key Retired and the external key Active, then hand off only the candidate anchor for independent pinning. |
| external-only finalization plan/apply | restricted node service identity after v3 migration, while the runtime is stopped | Verify the confirmed sweep and zero legacy-key chain/local-mempool exposure, remove the local secret from a generation-3 candidate, atomically rotate the v3 journal to that keyring anchor, then hand off both proposed anchors. External retirement/quiescence records remain operator assertions. |
| migration approval payload and plan | dedicated non-root/non-elevated node service identity while the node is stopped | This identity must have read-only, non-owner access to the policy, v2 external anchor, and keyring anchor. After plan, an independent control identity takes ownership of the validated snapshot at the exact path recorded in the plan and removes node write authority before apply. |
| migration apply | the same restricted node service identity, still offline | Apply validates the now-independent snapshot and creates the proposed v3 anchor in staging. The coordinator must install those exact bytes in its independently controlled live-anchor path before runtime. |
| v3 runtime | dedicated non-root/non-elevated node service identity | Read-only access to external controls, runtime passphrases, and both RPC authentication files; read/write access only to node-owned journal, keyring, and data files. |
| archive plan | restricted offline node service identity | The command creates both archive and pin, so the pin is not independent until it is transferred to another authority/path. |
| archive apply/verify | restricted offline node service identity | It may read but must not own, replace, or write the transferred manifest pin or any replacement-relevant ancestor. Transfer the proposed compacted anchor to the coordinator before restart. |

## Explicit keyring import

Stop the node first. The plan accepts either the legacy raw 32-byte Devnet key
or the passphrase-encrypted RCNet `wallet.key`. IDs are operator-generated
nonzero random 32-byte values; the tool never invents custody identities.

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node exchange-keyring-import-plan `
  --legacy-key-file C:\cmfd\node\wallet.key `
  --legacy-wallet-passphrase-file C:\cmfd-provisioning\wallet.passphrase `
  --keyring-instance-id <64-lowercase-hex> `
  --plan-output C:\cmfd-node-output\keyring-import-plan.json
```

Review the public key, key ID, candidate anchor, paths, and confirmation digest
in the plan. Apply only that exact digest:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node exchange-keyring-import-apply `
  --plan-file C:\cmfd-node-output\keyring-import-plan.json `
  --confirmation-digest <plan-confirmation-digest> `
  --keyring-passphrase-file C:\cmfd-provisioning\keyring.passphrase `
  --keyring-output C:\cmfd\node\exchange-keyring.bin `
  --anchor-output C:\cmfd-node-output\exchange-keyring.anchor
```

Outputs are create-new and exact retries are recoverable. The import does not
delete or rewrite `wallet.key`. The import identity initially creates both
outputs, so the staged anchor is not yet an independent rollback boundary.
Transfer the encrypted keyring file to the node service's owner-only custody
and verify that the runtime identity can read it.
If the imported key remains active, transfer its exact anchor bytes to
`C:\cmfd-controls\exchange-keyring.anchor` under the coordinator/control
identity, remove node and provisioner write authority, and use only that
handed-off path for migration and runtime. If an external signer will be used,
perform the transition below first and hand off the candidate anchor instead.
Likewise transfer the
wallet and keyring passphrases from their provisioner-owned staging files to
the confidential runtime external-secret paths under `C:\cmfd-controls`, grant
the node service read-only access, and remove its ownership/write authority.

## Explicit imported-keyring to external-key transition

Run this optional step after import and before migration when custody inputs
will be signed by an HSM, remote signer, or aggregate threshold-key service.
It accepts only a generation-1 imported keyring containing exactly one local
Active `DEPOSIT+CHANGE` key. The transition makes that legacy key Retired so it
can still sign already-owned v2 outputs and adds exactly one external Active
`DEPOSIT+CHANGE` key. It is not a general rotation command.

The plan binds the exact encrypted source envelope and trusted source anchor,
the external BIP340 public key and signer ID, the derived generation-2 anchor,
and all create-new output paths:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  exchange-keyring-external-transition-plan `
  --source-keyring-file C:\cmfd\node\exchange-keyring-imported.bin `
  --source-anchor-file C:\cmfd-provisioning\exchange-keyring-imported.anchor `
  --source-keyring-passphrase-file C:\cmfd-provisioning\keyring.passphrase `
  --external-public-key <64-lowercase-hex-x-only-BIP340-key> `
  --external-signer-id <64-lowercase-hex-stable-signer-id> `
  --keyring-output C:\cmfd\node\exchange-keyring.bin `
  --anchor-output C:\cmfd-provisioning\exchange-keyring.anchor `
  --plan-output C:\cmfd-node-output\external-keyring-transition-plan.json
```

Review both keys, signer ID, source and candidate anchors, source-envelope
digest, paths, and confirmation digest. Apply only that exact digest:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  exchange-keyring-external-transition-apply `
  --plan-file C:\cmfd-node-output\external-keyring-transition-plan.json `
  --confirmation-digest <plan-confirmation-digest> `
  --source-keyring-passphrase-file C:\cmfd-provisioning\keyring.passphrase
```

The imported envelope and anchor are never opened for writing. Candidate
outputs use create-new semantics, and an exact interrupted apply can be
retried. Transfer and pin the candidate anchor under the independent control
identity before migration, and bind the withdrawal policy's
`wallet_destination` to the candidate external public key. Retain the source
artifacts and import plan as recovery evidence.

This transition validates the external public key encoding and signer ID but
does not prove possession of the external private key or certify a provider.
Before receiving funds, complete a staging signing challenge through the exact
external protocol, verify the response, and rehearse provider outage and
recovery. For threshold custody, the keyring contains the service's single
aggregate BIP340 public key; the threshold ceremony and participant controls
remain inside the independently audited signer service.

Generation 2 is deliberately a **mixed migration stage**, not an HSM-only
state. Its Retired local key remains signable so v2 records and legacy outputs
can be migrated safely. The candidate must not be described as external-only,
and `wallet.key` remains a second path to the same legacy key outside the
keyring.

## Guarded external-only finalization

Run finalization only after v3 migration, after all withdrawals are terminal,
and with the v3 runtime stopped. It is a paired keyring/journal transition:
the generation-3 keyring replaces the Retired Local entry with Disabled
WatchOnly public metadata (the candidate envelope contains no local secret),
and one authenticated `RotateKeyring` journal generation pins that exact new
anchor. The tool creates both proposed anchors before committing the journal;
restart then fails closed until the independent control authority installs
both exact successors.

Finalization requires a strict external decommission assertion document:

```json
{
  "schema":"common-foundry-exchange-legacy-key-decommission-evidence-v1",
  "legacy_public_key":"<64-lowercase-hex>",
  "confirmed_sweep_txid":"<64-lowercase-hex>",
  "minimum_sweep_confirmations":"720",
  "deposit_address_retirement_assertion_digest":"<64-lowercase-hex>",
  "external_mempool_quiescence_assertion_digest":"<64-lowercase-hex>",
  "post_apply_wallet_key_disposition":"offline_quarantine_after_apply"
}
```

The node independently proves that the sweep transaction is on its active
chain, spends at least one legacy-key input, creates no legacy-key output, and
meets a compiled floor of 720 confirmations. It also requires zero active-chain
UTXOs of any maturity or timelock for the legacy key and zero outputs to that
key in the node's current local mempool at both plan and apply. The 720-block
floor is a conservative software safety floor, not economic finality.

The two assertion digests are only operator-supplied references bound into the
confirmed plan. The node does not authenticate the referenced retirement or
external-mempool records, cannot see transactions known only to other peers,
and cannot prevent a future payment or reorganization from exposing the old
address again. Keep deposit ingestion quiesced, retire the address in every
upstream system, inspect independent peers/mempools, and retain those records
outside the node before planning.

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v3.json `
  exchange-keyring-external-finalization-plan `
  --policy-file C:\cmfd-controls\withdrawal-policy.json `
  --source-keyring-file C:\cmfd\node\exchange-keyring.bin `
  --source-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --source-keyring-passphrase-file C:\cmfd-controls\keyring.passphrase `
  --legacy-public-key <legacy-public-key> `
  --decommission-evidence-file C:\cmfd-controls\legacy-decommission.json `
  --rotation-decision-id <unique-64-lowercase-hex> `
  --approval-digest <64-lowercase-hex-operator-authorization-reference> `
  --keyring-output C:\cmfd\node\exchange-keyring-external-only.bin `
  --keyring-anchor-output C:\cmfd-node-output\exchange-keyring-external-only.anchor `
  --journal-anchor-output C:\cmfd-node-output\withdrawal-anchor-external-only.json `
  --plan-output C:\cmfd-node-output\external-finalization-plan.json
```

`rotation_decision_id` and `approval_digest` are nonzero operator reference
metadata retained by the journal; this command does not verify a signature for
either. The full plan confirmation is the implemented authorization boundary.
Review the exact chain tip, sweep evidence, zero-exposure counters, source and
candidate keyring/journal anchors, assertion document and digest, and output
paths. Then apply that exact digest against the same current journal anchor and
chain tip:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v3.json `
  exchange-keyring-external-finalization-apply `
  --plan-file C:\cmfd-node-output\external-finalization-plan.json `
  --confirmation-digest <plan-confirmation-digest>
```

After apply, install both proposed anchors under the independent authority and
start the runtime with the generation-3 keyring. Move the original
`wallet.key`, generation-1 import artifacts, and generation-2 mixed keyring to
an offline quarantine outside the service identity rather than deleting them;
they are late-payment/reorganization recovery material and must never be used
by routine runtime. Monitor the retired address indefinitely. The tool never
moves, deletes, or quarantines `wallet.key`, and the result is only an
external-only **runtime candidate**—not consensus-enforced address retirement,
HSM vendor certification, or a production-custody claim.

## Policy document

The policy is strict JSON; atom quantities and thresholds are canonical
decimal strings. Public keys are unique and strictly sorted. Release and
cancel rosters are independent even when they intentionally contain the same
keys.

```json
{
  "schema":"common-foundry-exchange-withdrawal-policy-v1",
  "network_id":"<64-lowercase-hex>",
  "consensus_fingerprint":"<64-lowercase-hex>",
  "genesis_hash":"<64-lowercase-hex>",
  "wallet_destination":"<64-lowercase-hex>",
  "max_single_amount_atoms":"<decimal>",
  "max_single_fee_atoms":"<decimal>",
  "max_single_debit_atoms":"<decimal>",
  "max_rolling_24h_debit_atoms":"<decimal>",
  "max_rolling_24h_release_count":"<decimal>",
  "release_approval":{
    "threshold":"<decimal>",
    "public_keys":["<sorted-approver-key>"]
  },
  "cancel_approval":{
    "threshold":"<decimal>",
    "public_keys":["<sorted-approver-key>"]
  }
}
```

There are no compiled-in monetary limits or signer threshold. The policy ID
is derived from the validated policy and is bound by every approval and v3
journal snapshot. `wallet_destination` must equal the supplied keyring's one
Active CHANGE public key. During v2-to-v3 migration this may differ from the
legacy v2 wallet destination: migration separately requires that legacy key to
remain present, non-Disabled, and locally signable for the retained records.

## Explicit v2-to-v3 migration

Migration requires the v0.4 external anchor to equal the authenticated v2
journal, and every v2 record must already be Released. Before cutover, emit one
migration-scoped unsigned approval payload for each record while the exact v2
source anchor is still available:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v2.json `
  exchange-v3-migration-approval-payload `
  --policy-file C:\cmfd-controls\withdrawal-policy.json `
  --keyring-file C:\cmfd\node\exchange-keyring.bin `
  --keyring-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --keyring-passphrase-file C:\cmfd-controls\keyring.passphrase `
  --request-id <exact-v2-request-id> `
  --decision-id <unique-64-lowercase-hex> `
  --authorized-at-unix-seconds <decimal> `
  --expires-at-unix-seconds <later-decimal> `
  --output C:\cmfd-node-output\<request-id>.migration-approval.json
```

The command is read only except for its create-new output. It authenticates the
v2 snapshot and external anchor, validates the policy against the keyring's
Active CHANGE public key, separately proves the v2 wallet key is still local
and non-Disabled, binds the exact request digest, transaction signing digest,
and v2 source anchor, then prints the digest the release approvers sign. Add
the policy-required, strictly sorted `signatures` entries to that exact
payload. Repeat for every Released record.

Migration evidence schema v2 embeds each complete signed approval instead of
trusting parallel decision IDs, approval digests, or times:

```json
{
  "schema":"common-foundry-exchange-v3-migration-evidence-v2",
  "migration_id":"<64-lowercase-hex>",
  "migration_decision_id":"<64-lowercase-hex>",
  "migration_approval_digest":"<64-lowercase-hex>",
  "new_journal_instance_id":"<64-lowercase-hex>",
  "initial_policy_time_watermark_unix_seconds":"<decimal>",
  "released_records":[
    {
      "signed_approval":{
        "schema":"common-foundry-exchange-withdrawal-approval-v1",
        "action":"release",
        "decision_id":"<unique-64-lowercase-hex>",
        "policy_id":"<64-lowercase-hex>",
        "action_anchor":{
          "key_id":"<v2-source-key-id>",
          "journal_instance_id":"<v2-source-journal-instance-id>",
          "generation":"<decimal>",
          "commitment":"<v2-source-commitment>"
        },
        "request_id":"<exact-v2-request-id>",
        "request_digest":"<64-lowercase-hex>",
        "transaction_signing_digest":"<64-lowercase-hex>",
        "authorized_at_unix_seconds":"<decimal>",
        "expires_at_unix_seconds":"<later-decimal>",
        "signatures":[
          {"public_key":"<64-lowercase-hex>","signature":"<128-lowercase-hex>"}
        ]
      }
    }
  ]
}
```

The four top-level hexadecimal fields do not carry the same authority as each
record's verified `signed_approval`. `migration_id`, `migration_decision_id`,
and `new_journal_instance_id` are operator-supplied reference or instance
identifiers; generate independent, cryptographically random, nonzero 32-byte
values and retain their provenance. `migration_approval_digest` is also
operator-supplied reference metadata. The current implementation checks only
that these fields are canonical nonzero 32-byte values (and that the new
journal instance differs from the v2 source instance), then binds them into the
migration input, plan, journal, and receipt. It does not verify a signature or
approval document corresponding to `migration_decision_id` or
`migration_approval_digest`. If the latter is a digest of a separately retained
migration authorization record, document that convention externally; do not
treat the field as node-verified authorization. Review and confirmation of the
full `plan_digest` is the explicit cutover authorization.

Plan and apply independently reparse the canonical approval, verify its release
threshold signatures against the supplied policy at its signed authorization
time, and require the exact v2 source anchor, request, request digest, and
transaction signing digest. The terminal decision ID, approval digest, and
decision time are derived from that verified object. Evidence schema v1 and its
parallel text fields are rejected. Set the initial policy watermark to a
cutover horizon between the node's current clock and 15 minutes ahead. Planning
and apply both check that bound, and apply checks it again immediately before
publishing the initial anchor and activating the slots. Until that horizon the
new runtime rejects operations as clock regression.

v2 did not retain a trusted local submission time, so every imported Released
record is conservatively charged at that cutover horizon for a fresh 24-hour
window. The entire historical count and debit must fit the new rolling policy;
otherwise migration fails. Do not raise permanent production limits merely to
force a mature journal through this gate. Such a journal needs a separately
reviewed, independently evidenced 24-hour v2-withdrawal freeze procedure, which
this candidate does not implement. An empty v2 journal uses an empty
`released_records` array.

The v3 terminal representation changed during unreleased candidate development
to add durable local accounting time. Experimental v3 snapshots written by an
earlier working-tree build are unsupported and must not be reused or silently
converted. Before an RC cutover, confirm that no real-value state depends on an
earlier v3 snapshot; begin from an authenticated v2 source or from a fresh v3
instance using the exact reviewed binary and format.

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v2.json `
  exchange-v3-migration-plan `
  --evidence-file C:\cmfd-controls\migration-evidence.json `
  --policy-file C:\cmfd-controls\withdrawal-policy.json `
  --keyring-file C:\cmfd\node\exchange-keyring.bin `
  --keyring-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --keyring-passphrase-file C:\cmfd-controls\keyring.passphrase `
  --validated-snapshot-output C:\cmfd-snapshot-handoff\validated-v2.bin `
  --v3-anchor-output C:\cmfd-node-output\withdrawal-anchor-v3.proposed.json `
  --plan-output C:\cmfd-node-output\migration-plan.json
```

The plan identity creates the validated snapshot. Before apply, transfer
ownership/control of that same file and its replacement-relevant ancestor
directory at the exact plan-recorded path to the independent control identity,
and remove node write authority. Keep the proposed-anchor output in a separate
node-writable directory because apply must create it. Changing either path after
planning invalidates the plan.

Review the entire generated plan, including its data directory; plan and
validated-snapshot paths; journal-key path and derived key ID; evidence path
and digest; policy, keyring, anchor, and passphrase controls; deterministic v2
backup paths; proposed v3 external-anchor output; source and initial anchors;
retained Released count; and migration-input digest. Confirm the reported
domain-separated `plan_digest`, not the narrower migration-input digest, while
the node remains offline:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v2.json `
  exchange-v3-migration-apply `
  --plan-file C:\cmfd-node-output\migration-plan.json `
  --confirmation-plan-digest <full-plan-digest>
```

Apply reparses the CLI-selected plan and verifies its canonical full-plan
digest against that operator confirmation before resolving or opening any path
named inside the plan. Changing a key, control, backup, snapshot, or output
path—or changing the proposed initial anchor or migration input—requires a new
review and confirmation.

The apply phase retains create-new v2 backups before replacing either slot and
publishes the authenticated v3 marker last. It creates the v3 external anchor
without overwriting the v2 anchor. Do not rename one over the other until the
apply report and retained backups have been independently checked. The apply
report status is exactly
`applied; pin external_anchor_file independently before restart`. After those
checks, the coordinator installs the exact staged anchor bytes at
`C:\cmfd-controls\withdrawal-anchor-v3.json`, with the node restricted to read
access, and independently verifies the installed content before startup.

## Starting the v3 RPC

All v3 runtime inputs are required together. v3 cannot be activated with the
v0.4 withdrawal runtime, and it always requires the distinct withdrawal RPC
credential:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --wallet-passphrase-file C:\cmfd-controls\wallet.passphrase `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v3.json `
  run `
  --exchange-rpc-bind 127.0.0.1:38101 `
  --exchange-rpc-auth-file C:\cmfd-controls\integration-auth\integration.auth `
  --exchange-rpc-withdrawal-auth-file C:\cmfd-controls\withdrawal-auth\withdrawal.auth `
  --exchange-custody-v3-policy-file C:\cmfd-controls\withdrawal-policy.json `
  --exchange-custody-v3-keyring-file C:\cmfd\node\exchange-keyring.bin `
  --exchange-custody-v3-keyring-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --exchange-custody-v3-keyring-passphrase-file C:\cmfd-controls\keyring.passphrase
```

Startup fails before listening if bindings, policy, keyring, journal,
activation marker, v3 RPC external-secret files, ACLs, or external ancestry do
not validate. On success, startup identifies `chain-preview-v0.5`, includes
top-level `"exchange_rpc_custody":"v3"`, and reports nested status
`"exchange_custody_v3_wallet_state":"active"`.

There is no v0.5 offline journal-info command, and a failed startup provides no
listener, but its public error message now distinguishes an external anchor
that `is ahead of` the authenticated journal from one that `diverges from` it.
A behind, replay-safe authenticated ancestor may start for observation;
state-changing operations require the current anchor and report that it
`is behind` until the coordinator advances it. These cases retain the common
machine classification
`exchange_custody_v3_anchor_mismatch`. Preserve the journal, marker, key, and
anchor byte-for-byte and follow the distinct recovery row below; never edit or
force either file merely to make startup or a mutation pass.

## v0.5 withdrawal RPC

The chain, mempool, deposit-watch, and deposit-event methods remain the v0.4
contract. The separately authenticated v0.5 withdrawal methods are:

| Method | Positional parameters | Effect |
|---|---|---|
| `preparewithdrawal` | `[request_id, destination_hex, amount_atoms, fee_atoms]` | Atomically persists an unsigned plan and reservations |
| `getwithdrawalsigningpackage` | `[request_id, signed_approval_object]` | Only after the exact `ReleaseAuthorized` anchor is externally pinned, verifies that same persisted approval and returns the exact package plus its authorization envelope; read only |
| `getwithdrawalapprovalpayload` | `[request_id, action, decision_id, authorized_at_unix_seconds, expires_at_unix_seconds]` | Returns a wrapper containing `approval_document`, its exact base64 bytes, and the approval signing digest; read only |
| `releasewithdrawal` | `[request_id, signed_approval_object, external_signer_responses?]` | First call durably authorizes and returns; after its anchor is pinned, an exact retry signs locally or verifies the optional ordered response array, durably releases, and submits exact bytes |
| `cancelwithdrawal` | `[request_id, signed_approval_object]` | Durably cancels before releasing reservations |
| `getwithdrawal` | `[request_id]` | Returns durable evidence and live mempool/chain observation; read only |
| `getwithdrawaljournalinfo` | `[]` | Returns current/external anchors, policy and keyring IDs, watermark, and storage health; read only |

`getwithdrawaljournalinfo` also returns exact live-record, tombstone, and
commitment counts and limits, a conservative estimate of how many complete
five-transition releases remain, and a warning below 1,024 estimated releases.
This is an alarm, not a rollover mechanism. Canceled-only compaction cannot
prevent eventual exhaustion from Released records; production remains blocked
until a finality/reorg policy and tested released-record archive plus journal
epoch rollover are designed and independently reviewed.

### Signer-package byte contract

`signer_package_base64` is standard base64 of the exact canonical
`SigningPackageV1` binary envelope. It is not JSON. A decoder must reject
truncation, trailing bytes, noncanonical re-encoding, and any field mismatch.
All multibyte integers are little-endian and all IDs, digests, commitments, and
x-only public keys below are raw 32-byte values:

| Bytes | Meaning |
|---|---|
| 8 | ASCII `CMFDSIG1` |
| 2 | protocol version `1` as `u16` |
| 1 | message kind `2` for signing package |
| 1 | reserved zero byte |
| 4 | payload length as `u32`, exactly the remaining byte count |
| 32 + 32 + 32 | network ID, consensus fingerprint, genesis hash |
| 32 + 32 + 8 + 32 | Prepared anchor key ID, journal instance ID, generation, commitment |
| 2 + variable | request-ID byte length as `u16`, then its UTF-8/visible-ASCII bytes |
| 32 + 32 | request digest, policy ID |
| 32 + 8 + 32 | keyring instance ID, generation, commitment |
| 4 + variable | unsigned-transaction length as `u32`, then canonical transaction bytes with each key-witness signature exactly 64 zero bytes |
| 32 | consensus transaction signing digest |
| 2 + repeated records | input count as `u16`, followed by the input records below |

Each input record is `input_index:u32`, outpoint txid (32 bytes), outpoint
index `u32`, `value_atoms:u64`, wallet key ID (32 bytes), public key (32 bytes),
signer ID (32 bytes), and capability digest (32 bytes), in that order.

`signer_package_digest` is BLAKE3 derive-key-context mode with context
`CMFD/NODE/SIGNING-PACKAGE/V1` over the entire exact envelope.
`signer_package_bytes_digest` is separately BLAKE3 derive-key-context mode with
context `CMFD/NODE/EXCHANGE-WITHDRAWAL-SIGNER-PACKAGE/V3` over the exact byte
length as `u64` little-endian followed by the exact envelope. Do not substitute
one digest for the other. The in-tree golden fixture
`wallet_signing_protocol::tests::golden_digests_and_signed_transaction_are_stable`
fixes the first 16 package bytes at
`434d4644534947310100020098040000` and its `signer_package_digest` at
`e349e9e9a01caab82b04ad0ed5a4da768c248675c20525d096c6e04a21ab9379`.

Ordinary `preparewithdrawal` and `getwithdrawal` responses intentionally expose
only package digests. Exact package bytes are available solely through
`getwithdrawalsigningpackage` after `ReleaseAuthorized` and its external anchor
match, and only when the caller resubmits the exact persisted release approval.
The returned `release_authorization` object includes that approval and the
`ReleaseAuthorized` anchor so a signer-side policy service can compare the
anchor with its independently replicated pin before asking an HSM to sign. It
also returns `release_authorization_digest`, computed with BLAKE3
derive-key-context `CMFD/NODE/SIGNING-RELEASE-AUTHORIZATION/V1` over the exact
package digest, ReleaseAuthorized anchor fields, decision ID, and approval
digest.

The result also exposes `approval_action_anchor`, the exact journal anchor in
the signed approval. It is later than the package's `prepared_anchor`, but it
need not be the immediately following generation because this journal is
global and unrelated transitions may interleave. `current_anchor` and
`release_authorization.release_authorized_anchor` must be the exact next
generation after `approval_action_anchor`, with the same journal key and
instance identities. A signer must bind all three anchors independently; it
must not infer the approval anchor from the request's Prepared generation.

Each optional `external_signer_responses` entry is standard base64 of a
canonical `SignerResponseV1` frame (`CMFDSIG1`, version 1, kind 3). Responses
must be strictly ordered by signer ID and include exactly the inputs assigned
to that signer. The node derives signer IDs, capabilities, public keys, and
complete key-set digests from its independently authenticated keyring; it does
not trust those values merely because a package or remote peer supplied them.
Every input carries both a consensus BIP340 signature and a second BIP340
package-authorization signature binding the exact package, post-authorization
digest, input, wallet key, signer identity, capability, and consensus
signature. A response payload starts with the 32-byte package digest, 32-byte
release-authorization digest, 32-byte signer ID, 32-byte capability digest,
then a `u16` signature count and its fixed-field input-signature records.
Missing, duplicate, extra, reordered, wrong-key, wrong-package,
wrong-authorization, or invalid responses fail closed. In particular, a
response made from the Prepared package before `ReleaseAuthorized` cannot be
replayed as an authorized response.

For independent signer conformance, the same in-tree golden fixture fixes its
first input's package-authorization digest at
`c6a521beb768661cbcf5ad678a01e74c7bd05581f1fa5ee525cf9ee81054502d`
and the first canonical response digest at
`ffe964fbde15905b04b6193fd53639cfac7f6a10e021b2e5dc3205576ac03e26`.
An adapter should reproduce these values before it is allowed to handle a
staging key.

This is the node-side HSM/remote integration boundary, not a vendor driver or a
public remote-signing server. The exchange RPC remains loopback-only. A
deployment sidecar must authenticate and encrypt its signer transport, pin the
signer software/configuration and key-set identity, enforce its own approval
and clock rules, and qualify the actual HSM or threshold implementation.
External private key material is never loaded by the keyring coordinator, and
the custody destination may differ from the node's unrelated local wallet key.

The in-tree `cmfd-exchange-signer-reference` is a stateless software-key
conformance aid. In addition to the node result, it requires an independently
BIP340-authenticated context that binds the package, transaction intent,
signer capability/key set, approval roster, and all three anchors. Its context
authority public key must be pinned outside the request path. The reference
does not prove package input values against chain state, persist a replay
ledger, implement an HSM/remote transport, or qualify Windows ACL and physical
power-loss behavior; those remain production-adapter requirements.

The approval roster is true M-of-N authorization. Consensus inputs remain
single BIP340-key locks. Multiple signer services may sign different inputs in
one transaction; threshold control of one such key must be implemented behind
one aggregate public key by an independently reviewed FROST/MuSig-style or HSM
service. This code does not claim that threshold implementation itself.

### Approval object and signing contract

`getwithdrawalapprovalpayload` returns a result wrapper. Copy
`result.approval_document`, add the strictly public-key-sorted `signatures`
entries to that nested object, and submit the nested object as `params[1]`.
Do not submit the entire result wrapper. Each signature entry is
`{"public_key":"<64-hex>","signature":"<128-hex>"}`. For example:

```json
{
  "jsonrpc":"2.0",
  "id":"release-1",
  "method":"releasewithdrawal",
  "params":[
    "withdrawal-0001",
    {
      "schema":"common-foundry-exchange-withdrawal-approval-v1",
      "action":"release",
      "decision_id":"<64-lowercase-hex>",
      "policy_id":"<64-lowercase-hex>",
      "action_anchor":{
        "key_id":"<64-lowercase-hex>",
        "journal_instance_id":"<64-lowercase-hex>",
        "generation":"<decimal>",
        "commitment":"<64-lowercase-hex>"
      },
      "request_id":"withdrawal-0001",
      "request_digest":"<64-lowercase-hex>",
      "transaction_signing_digest":"<64-lowercase-hex>",
      "authorized_at_unix_seconds":"<decimal>",
      "expires_at_unix_seconds":"<later-decimal>",
      "signatures":[
        {"public_key":"<64-lowercase-hex>","signature":"<128-lowercase-hex>"}
      ]
    }
  ]
}
```

For cancellation, use the same nested-object rule with method
`cancelwithdrawal`, action `cancel`, and the exact action anchor returned for
that payload. Generate every terminal `decision_id` as a fresh, globally unique,
nonzero 32-byte value. Never reuse it for another request or action, including
after compaction; the journal enforces uniqueness across live records and
tombstones.

The wrapper's `signing_digest` is the **approval** signing digest. It is distinct
from the nested `transaction_signing_digest`. It is ordinary BLAKE3 over this
exact byte concatenation:

```text
"CMFD/NODE/EXCHANGE-WITHDRAWAL-ACTION/V1\0"
|| action_tag:u8                         # release=1, cancel=2
|| policy_id[32]
|| action_anchor.key_id[32]
|| action_anchor.journal_instance_id[32]
|| action_anchor.generation:u64le
|| action_anchor.commitment[32]
|| request_id_length:u16le
|| request_id_bytes
|| request_digest[32]
|| transaction_signing_digest[32]
|| decision_id[32]
|| authorized_at_unix_seconds:u64le
|| expires_at_unix_seconds:u64le
```

Approvers produce BIP340/secp256k1 Schnorr signatures by passing those raw 32
digest bytes as the signing message. Do not sign the 64 ASCII hexadecimal
characters, the JSON, or the base64 document, and do not add an application
prehash before the Schnorr API. The existing release-action golden vector uses
policy ID
`b081b67dcf4d7983b6c2d01fb6156ac9c55afe0bffbdbc777dca0653b95bbe3c`,
anchor fields `05` repeated 32, `06` repeated 32, generation 7, and `08`
repeated 32; request ID `withdrawal-0001`; request digest `09` repeated 32;
transaction signing digest `0b` repeated 32; decision ID `0a` repeated 32; and
times 1800000000 and 1800000600. Its approval signing digest is
`9cbb3e7d09210c6f79ced6bd39d7888806b85aa5859a340a9cb4e9cc029e04a2`.

The validity times are signed Unix seconds. `expires_at_unix_seconds` must be
no more than 900 seconds after `authorized_at_unix_seconds`; the node must be
inside that interval. The signed authorization time is retained in terminal
evidence, while the node's durable, monotonic submission-time watermark is
stored as `accounted_at_unix_seconds` and used for rolling 24-hour accounting.
The status document exposes both times. This prevents long-lived backdated
approvals from moving immediate releases outside the active window. Amounts,
generations, counts, confirmations, and times are returned as canonical
decimal strings where JSON number precision could be ambiguous.

The exception is an already Released record imported from v2: its retry
approval payload is the canonical payload embedded in the retained
migration-evidence v2 file. `getwithdrawalapprovalpayload` intentionally cannot
create a new approval for a terminal record. A manual or reorg retry must
resubmit that payload with a policy-valid threshold signature set; the runtime
verifies it and broadcasts only the authenticated stored transaction bytes.

After every state-changing `preparewithdrawal`, `releasewithdrawal`, or
`cancelwithdrawal`, atomically replace the coordinator-owned external anchor
with the exact returned `anchor`. A release therefore requires two successful
state changes and two pins: `Prepared` to `ReleaseAuthorized`, then
`ReleaseAuthorized` to `Released`. Never pin a request merely because an HTTP
request was sent. If a response is lost, use `getwithdrawal` to recover and
verify the durable phase before advancing the anchor, then retry only the same
request and signed terminal action.

After durably saving the complete successful JSON-RPC response, the offline
helper accepts `chain-preview-v0.5`, validates the exact top-level four-field
`result.anchor`, rejects rollback/key/instance/same-generation divergence, and
performs same-directory atomic replacement:

```powershell
.\scripts\pin-exchange-withdrawal-anchor.ps1 `
  -ResponseFile C:\cmfd-coordinator\release-response.json `
  -AnchorPath C:\cmfd-controls\withdrawal-anchor-v3.json
```

The helper never contacts RPC and cannot decide that a response is authorized;
invoke it only after the exchange database has matched and committed the exact
request, phase, approval, and response.

## Canceled-record archive and compaction

Released-record pruning is disabled because no chain-finality rule is part of
v0.5. Only explicitly selected, terminal Canceled records may be compacted.
Stop the node and first create an authenticated archive plus a separate
manifest-pin artifact:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v3.json `
  exchange-v3-archive-plan `
  --policy-file C:\cmfd-controls\withdrawal-policy.json `
  --keyring-file C:\cmfd\node\exchange-keyring.bin `
  --keyring-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --keyring-passphrase-file C:\cmfd-controls\keyring.passphrase `
  --request-id <canceled-request-id> `
  --archive-output C:\cmfd-archive\canceled.bin `
  --manifest-pin-output C:\cmfd-node-output\canceled.pin
```

The plan command creates both artifacts as its own execution identity; that
alone does not establish an independent pin. Before apply, retain the archive
separately and transfer the manifest pin to an independent authority/path. The
apply identity must be able to read the pin but must not be able to modify,
delete, replace, or take control of it or its replacement-relevant directory
chain. On Unix this requires a separate non-root owner/control identity (or an
equivalent read-only mount); on Windows it requires an ACL-separated control
path. Apply and restore verification fail closed if this boundary is absent.

After that transfer, confirm the exact archive ID to the apply command and
provide a create-new proposed-anchor path. The tool never overwrites the live
external anchor. Pin the proposal only after the command reports
`journal_compacted; pin proposed_anchor_file independently before restart`:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  --exchange-withdrawal-anchor-file C:\cmfd-controls\withdrawal-anchor-v3.json `
  exchange-v3-archive-apply `
  --policy-file C:\cmfd-controls\withdrawal-policy.json `
  --keyring-file C:\cmfd\node\exchange-keyring.bin `
  --keyring-anchor-file C:\cmfd-controls\exchange-keyring.anchor `
  --keyring-passphrase-file C:\cmfd-controls\keyring.passphrase `
  --archive-file C:\cmfd-archive\canceled.bin `
  --manifest-pin-file C:\cmfd-controls\canceled.pin `
  --confirmation-archive-id <64-lowercase-hex> `
  --proposed-anchor-output C:\cmfd-node-output\compacted-anchor.proposed.json
```

After success, the coordinator must verify that the proposed file exactly
encodes the reported `compacted_anchor`, then atomically install those exact
bytes at the live external-anchor path before restart. The RPC-response pinning
helper does not consume an archive-apply report or proposed-anchor file. The
apply identity must not retain write authority to the live path.

Offline restore verification authenticates the archive and exact independent
pin without writing any journal state:

```powershell
.\cmfd-node.exe --data-dir C:\cmfd\node `
  --exchange-withdrawal-journal-key-file C:\cmfd-node-secrets\withdrawal-journal.key `
  exchange-v3-archive-verify `
  --archive-file C:\cmfd-archive\canceled.bin `
  --manifest-pin-file C:\cmfd-controls\canceled.pin
```

Archive verification requires the journal key and independent manifest pin; it
does not require or consult the live external journal anchor.

Compacted tombstones retain keyed request identity, request and approval
digests, terminal decision, archive ID, and payload digest so a compacted
request ID cannot be reused.

## Deterministic copy-only crash rehearsal

`scripts\rehearse-exchange-custody-v3.ps1` exercises migration recovery without
writing the source node directory. `Stage` requires the source node to be
stopped, takes a non-sharing handle to its existing `node.lock`, hashes and
copies every non-reparse file into a create-new protected rehearsal root, and
runs the normal migration-plan command against that copy:

```powershell
.\scripts\rehearse-exchange-custody-v3.ps1 -Mode Stage `
  -RehearsalRoot C:\cmfd-rehearsal\run-001 `
  -NodeBinary C:\cmfd\cmfd-node.exe `
  -SourceDataDir C:\cmfd\node `
  -WalletPassphraseFile C:\cmfd-controls\wallet.passphrase `
  -JournalKeyFile C:\cmfd-node-secrets\withdrawal-journal.key `
  -V2AnchorFile C:\cmfd-controls\withdrawal-anchor-v2.json `
  -EvidenceFile C:\cmfd-controls\migration-evidence.json `
  -PolicyFile C:\cmfd-controls\withdrawal-policy.json `
  -KeyringAnchorFile C:\cmfd-controls\exchange-keyring.anchor `
  -KeyringPassphraseFile C:\cmfd-controls\keyring.passphrase `
  -ValidatedSnapshotOutput C:\cmfd-snapshot-handoff\run-001\validated-v2.bin
```

`ValidatedSnapshotOutput` must be create-new and outside both the source and
rehearsal roots; putting it below the service-owned rehearsal root would defeat
the external-control independence check. Stage deliberately stops after writing
its report. Transfer ownership/control of the reported
`validated_snapshot_file` and its replacement-relevant parent chain to the
independent control identity exactly as required for the real migration. Review
and confirm the complete staged plan. Then run `Exercise` as the intended
apply/service identity with the exact reported plan digest:

```powershell
.\scripts\rehearse-exchange-custody-v3.ps1 -Mode Exercise `
  -RehearsalRoot C:\cmfd-rehearsal\run-001 `
  -NodeBinary C:\cmfd\cmfd-node.exe `
  -SourceDataDir C:\cmfd\node `
  -WalletPassphraseFile C:\cmfd-controls\wallet.passphrase `
  -JournalKeyFile C:\cmfd-node-secrets\withdrawal-journal.key `
  -V2AnchorFile C:\cmfd-controls\withdrawal-anchor-v2.json `
  -ConfirmationPlanDigest <exact-staged-plan-digest>
```

Exercise first completes one golden migration on the disposable copy. It then
reconstructs and resumes the exact on-disk states before/after proposed-anchor
creation, after each of the three v2 backups, after each v3 slot replacement,
and after the authenticated activation marker. Each recovery must converge to
the same custody-file, proposed-anchor, and encrypted-keyring checksums. Unless
`-SkipRustMatrix` is explicitly supplied, it also runs the focused Rust matrix
that injects a failure after temporary-file sync but before atomic publication
for release authorization, release completion, cancellation, and compaction;
each old and new state is reopened and its journal, anchor relationship, and
keyring binding are verified. The create-new final report is
`exchange-custody-rehearsal-evidence.json` under the protected rehearsal root.

This is deterministic crash-state injection, not a physical power cut. It does
not qualify controller write caches, filesystem/barrier behavior, UPS policy,
or the deployed host. Preserve the report as private custody evidence, then run
a separate abrupt-power-loss rehearsal on the target storage stack using only
non-production keys and independently retained controls.

## Failure and recovery expectations

| Observed durable phase | Safe operator action |
|---|---|
| `Prepared` | Pin its exact anchor; obtain one release or cancel approval |
| `ReleaseAuthorized` | Pin its exact anchor; for external keys, fetch the authorized package with the same approval and collect canonical signer responses; then retry release with that approval and any required responses; do not cancel or refund policy budget |
| `Released` / `broadcast_pending` | Retry release with that same canonical approval payload and a valid threshold signature set to submit only stored bytes |
| `Released` / `in_mempool` | Observe; do not create a replacement transaction |
| `Released` / `confirmed` | Apply the exchange's independent confirmation/finality policy |
| `Released` / `conflicted` | Stop and investigate; do not edit the journal |
| `Canceled` | Pin the returned anchor; its inputs are available to new plans |
| RPC reports anchor relationship `descendant`, or mutation says the external anchor `is behind` | The authenticated journal extends the coordinator pin. Recover and verify each missing durable response, then atomically advance the coordinator anchor to the exact current anchor before another mutation. |
| startup says the external anchor `is ahead of` the authenticated journal | Hard stop. Restore the independently retained journal state that exactly reaches that pin, or revert the coordinator file only from independently authenticated evidence; never infer or force a value. |
| startup says the external anchor `diverges from` the authenticated journal | Hard stop. Preserve both artifacts and restore one independently verified matching journal-and-anchor history; never select a side by generation alone. |

## Remaining release gates

This milestone provides local and provider-neutral external signing paths, not
a production custodian or a certified HSM/threshold product. Before real-value
exchange use it still requires an independent custody and cryptographic audit,
Windows and Linux packaged-binary qualification using the live ACL gate (a
fixture result does not satisfy it), backup/restore and physical power-loss
rehearsals on the deployed storage stack, vendor-specific HSM/remote/threshold
conformance and failure testing, multi-node deposit/confirmation policy,
service-identity provisioning, and exchange-specific load/runbook testing.
Action-approval thresholds do not turn a one-key consensus input into native
on-chain multisig.
