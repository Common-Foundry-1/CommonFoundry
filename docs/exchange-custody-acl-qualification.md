# Exchange custody packaged-host ACL qualification

Status: implemented v0.5 deployment gate. This gate qualifies one installed
package and one fully provisioned custody path set on Windows or Linux. It does
not qualify key management, signing policy, backups, storage power-loss
behavior, filesystem locality/durability semantics, or the exchange's
surrounding systems.

The live gate is an in-process `cmfd-node` command. It does not parse
`icacls`, `getfacl`, or mode-command output. It runs the production
retained-handle custody validators with the current process token, so launch it
as the exact dedicated node service identity that will run custody. Running it
as `root`, LocalSystem, or an elevated Windows administrator is rejected.

## Fixed identities and material contract

The configuration names three distinct installed identities. The qualifier
resolves each name to a UID on Linux or SID on Windows and rejects a missing or
shared identity.

| Identity | Authority |
|---|---|
| service | Runs `cmfd-node`; owns node-writable data and node secrets |
| operator | Owns the installed node binary, policy, runtime passphrases, and both RPC credentials |
| anchor | Independently owns the journal and keyring rollback anchors |

The ten configured artifacts are fixed; extra or omitted names are invalid:

| Configuration field | Class | Required owner | Required location |
|---|---|---|---|
| `data_directory` | node directory | service | node data directory |
| `journal_key` | node secret | service | outside data directory |
| `withdrawal_anchor` | external control | anchor | outside data directory |
| `policy` | external control | operator | outside data directory |
| `keyring` | node secret | service | inside data directory |
| `keyring_anchor` | external control | anchor | outside data directory |
| `wallet_passphrase` | external secret | operator | outside data directory |
| `keyring_passphrase` | external secret | operator | outside data directory |
| `integration_rpc_auth` | external secret | operator | outside data directory |
| `withdrawal_rpc_auth` | external secret | operator | outside data directory |

Every path must already exist as a direct, non-link file or directory. Symlinks,
Windows reparse points, missing artifacts, duplicate paths, and an absent
installed package fail closed. The package root name is exactly
`commonfoundry-rc-runtime-windows-x86_64` or
`commonfoundry-rc-runtime-linux-x86_64`; the command must be executing the
`cmfd-node[.exe]` inside that configured root. The binary must be owned by the
operator identity and its SHA-256 is recorded in evidence.

On Windows, each qualified object requires a valid owner and non-null protected
DACL containing only standard allow/deny ACEs. In addition to the runtime
checks, qualification resolves an exact authority allowlist for each artifact.
Every checked owner and every protected allow ACE carrying a relevant read or
mutation right must name a SID in that artifact's allowlist. The fixed base is
service-only for node material, service plus operator for the package and
operator controls, and service plus anchor for anchor controls. Arbitrary extra
SIDs fail even when they are neither a built-in broad principal nor the current
service SID. LocalSystem, Administrators, and TrustedInstaller are not implicit:
list an OS authority under `windows_additional_authorities` only where the
installed owner or DACL actually requires it. A listed account is an accepted
existing authority, not an instruction to grant it access, and allowlisting
never relaxes the production runtime policy.

Node-owned sensitive access remains limited by the production validator to the
service SID, LocalSystem, or Administrators. External controls require effective
service read access without service mutation, delete, ownership, or DACL
authority. External-secret read access cannot be granted to a broad principal.
The complete replacement-relevant ancestor chain through the volume root is
validated against the same per-artifact allowlist, and inherited, broadly
writable, or unlisted authority is rejected.

On Linux, the service EUID must be nonzero. Its real, effective, saved-set, and
filesystem UIDs must all match; its real, effective, saved-set, and filesystem
GIDs must likewise match one another; and its inheritable, permitted, effective,
and ambient capability sets must all be empty. Set-UID execution and ambient or
file capabilities are therefore not accepted substitutes for an unprivileged
service account. Each named identity resolves to an explicit `uid:<number>`
authority. Root (`uid:0`) is recorded as the privileged OS boundary needed for
ordinary `/`, `/opt`, and `/var` ancestors; it is not an additional custody
role. Node-owned secrets and the data directory must be owner-only. External
files must have a different owner from the service and
must not be effectively writable by it; neither may any replacement-relevant
ancestor, including every ancestor of the node data directory. Public controls
reject group/other write bits. External secrets additionally reject all
other-user access while allowing an explicitly configured dedicated group to
provide service read access.

Every configured Unix group resolves to an explicit `gid:<number>` authority.
The qualifier enumerates both its supplementary members and accounts whose
primary GID matches, and rejects the group if any member UID is not one of that
artifact's fixed service/operator/anchor UIDs (or root). A group-writable
ancestor is accepted only when that GID is explicitly listed for the artifact.
Any extended POSIX access ACL, and any default ACL on a directory, fails closed;
mode bits remain the sole accepted Linux discretionary-access representation.
Failure to query the POSIX ACL xattr namespace, including `ENOTSUP`, also fails
closed rather than being interpreted as proof that no ACL exists.
All ancestor directories are opened without following the final component,
retained through validation, and rechecked for replacement. Opened file
identity is likewise checked again to reject replacement races. Final evidence
must be collected only where the system's NSS account database can enumerate
the complete group and primary-GID membership set.

## Live configuration and invocation

The configuration is strict JSON:

```json
{
  "schema": "common-foundry-exchange-custody-acl-config-v1",
  "package_root": "C:\\Program Files\\commonfoundry-rc-runtime-windows-x86_64",
  "identities": {
    "service": ".\\cmfd-node-service",
    "operator": ".\\cmfd-custody-operator",
    "anchor": ".\\cmfd-anchor-controller"
  },
  "windows_additional_authorities": {
    "package": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "data_directory": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"],
    "journal_key": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"],
    "withdrawal_anchor": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "policy": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "keyring": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"],
    "keyring_anchor": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "wallet_passphrase": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "keyring_passphrase": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "integration_rpc_auth": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"],
    "withdrawal_rpc_auth": ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "NT SERVICE\\TrustedInstaller"]
  },
  "unix_authority_groups": {
    "package": [],
    "data_directory": [],
    "journal_key": [],
    "withdrawal_anchor": [],
    "policy": [],
    "keyring": [],
    "keyring_anchor": [],
    "wallet_passphrase": [],
    "keyring_passphrase": [],
    "integration_rpc_auth": [],
    "withdrawal_rpc_auth": []
  },
  "artifacts": {
    "data_directory": "C:\\ProgramData\\CommonFoundry\\node",
    "journal_key": "C:\\ProgramData\\CommonFoundry\\node-secrets\\withdrawal-journal.key",
    "withdrawal_anchor": "C:\\ProgramData\\CommonFoundryControls\\anchors\\withdrawal-anchor-v3.json",
    "policy": "C:\\ProgramData\\CommonFoundryControls\\policy\\withdrawal-policy.json",
    "keyring": "C:\\ProgramData\\CommonFoundry\\node\\exchange-keyring.bin",
    "keyring_anchor": "C:\\ProgramData\\CommonFoundryControls\\anchors\\exchange-keyring.anchor",
    "wallet_passphrase": "C:\\ProgramData\\CommonFoundryControls\\secrets\\wallet.passphrase",
    "keyring_passphrase": "C:\\ProgramData\\CommonFoundryControls\\secrets\\keyring.passphrase",
    "integration_rpc_auth": "C:\\ProgramData\\CommonFoundryControls\\secrets\\integration.auth",
    "withdrawal_rpc_auth": "C:\\ProgramData\\CommonFoundryControls\\secrets\\withdrawal.auth"
  }
}
```

Use installed account names, not the placeholders above. Remove any example OS
authority not present in the actual retained-handle owner/DACL chain; adding a
name merely to make a check pass expands the declared trust boundary. Every
configured name must resolve, and two names resolving to the same SID are
rejected. On Linux, every `windows_additional_authorities` list must be empty.
Use `unix_authority_groups` only for a GID actually needed by that artifact's
mode or ancestor chain; an unnecessary entry expands the declared boundary and
is rejected if it contains an unrelated member.

Stop the node and run the package under its actual non-elevated service token.
The wrapper does not change identity:

```powershell
.\scripts\qualify-exchange-custody-acl.ps1 `
  -NodeExecutable 'C:\Program Files\commonfoundry-rc-runtime-windows-x86_64\cmfd-node.exe' `
  -Config 'C:\cmfd-qualification\acl-config.json' `
  -Output 'C:\cmfd-qualification\acl-evidence.json'
```

Linux uses the same schema with absolute Linux paths and installed account
names. For example, an operator-owned `0440` external secret read by the service
may name its dedicated, audited group only on the corresponding secret fields:

```json
"unix_authority_groups": {
  "package": [],
  "data_directory": [],
  "journal_key": [],
  "withdrawal_anchor": [],
  "policy": [],
  "keyring": [],
  "keyring_anchor": [],
  "wallet_passphrase": ["cmfd-custody-readers"],
  "keyring_passphrase": ["cmfd-custody-readers"],
  "integration_rpc_auth": ["cmfd-custody-readers"],
  "withdrawal_rpc_auth": ["cmfd-custody-readers"]
}
```

Run the qualifier as the installed service identity:

```bash
sudo -u cmfd-node-service -- \
  ./scripts/qualify-exchange-custody-acl.sh \
  --node /opt/commonfoundry-rc-runtime-linux-x86_64/cmfd-node \
  --config /etc/commonfoundry/acl-config.json \
  --output /var/lib/commonfoundry-qualification/acl-evidence.json
```

`sudo` is only an example way for an administrator to start the already
provisioned unprivileged account; the resulting node EUID must be the configured
service UID. Prefer the real service manager's execution context for final
evidence. The output path must be absolute and absent. Evidence is create-new;
the command returns nonzero after writing a rejected live evaluation.

Keyring import is different: its plan/apply passphrases remain protected
provisioner-owned inputs. Migration plan/apply, archive operations, the live
runtime, and this live qualification run as the actual service identity and
consume the handed-off independent runtime passphrase/control chain.

## Evidence contract

Evidence schema is
`common-foundry-exchange-custody-acl-qualification-v1`. A deployable result
requires all of:

- `qualification_scope` is `installed_host`;
- `result` is `host_qualified`;
- `host_qualified` is `true` and `fixture_qualified` is `false`;
- every entry in `checks` has `status: "pass"`; and
- the recorded package SHA-256 and configured paths match the release and
  service configuration being deployed.

The evidence also records `evaluated_at_unix_seconds` and the SHA-256 of the
exact retained-handle input document as `input_document_sha256`. Package and
artifact facts expose the resolved `allowed_authority_ids` and
`authority_allowlist_valid`. On Windows these are SIDs; on Linux they are
canonical `uid:` and `gid:` values. Any false allowlist result, unresolved or
duplicate authority, unlisted owner/writer, unaudited group membership, or
extended POSIX ACL rejects host qualification.

Any other combination is not host qualification. Preserve the evidence with
the package manifest and service configuration. Successful v0.5 startup with
`exchange_custody_v3_wallet_state: "active"` remains the final retained-state
gate after ACL qualification. Host qualification does not prove that a path is
on a local filesystem or that the filesystem/controller honors the required
flush and atomic-replacement semantics; the target-storage migration and
physical power-loss rehearsal remains a separate release gate.

## Dry fixture mode

Fixture mode tests the strict evidence evaluator without asserting anything
about the current machine. Its input schema is
`common-foundry-exchange-custody-acl-fixture-v1`; it contains normalized
identity, package, and artifact facts in the same fixed ordering as live
evidence, including explicit `allowed_authority_ids` and
`authority_allowlist_valid` facts. A passing fixture returns
`result: "fixture_qualified"`,
`fixture_qualified: true`, and always `host_qualified: false`.

The checked-in test vector can exercise either wrapper locally:

```powershell
.\scripts\qualify-exchange-custody-acl.ps1 `
  -NodeExecutable (Resolve-Path .\target\debug\cmfd-node.exe).Path `
  -Fixture (Resolve-Path .\scripts\tests\exchange-custody-acl-safe-windows.json).Path `
  -Output C:\Temp\cmfd-acl-fixture-evidence.json
```

Fixture booleans are test inputs, not observations. A person can author a
passing fixture, so fixture evidence must never be attached to a host-readiness
claim or relabeled as installed-host evidence.
