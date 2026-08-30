# Authenticated update and rollback qualification

The update/rollback gate proves that a Common Foundry installation can move
between two authenticated releases without silently changing networks or
losing its last known-good version. The qualification harness is
`scripts/update_rollback_qualification.py`.

## Security boundary

Both release directories are authenticated with the source-free
`release_integrity.py verify-download` path before any installation command is
allowed to run. The harness requires:

- valid OpenSSH Ed25519 signatures under the fixed
  `commonfoundry-release` namespace
- the same signer identity, allowed-signers policy, and verifier on both
  releases
- a strictly newer semantic version for the candidate
- identical network ID, network name, and virtual-genesis hash
- an authenticated `NETWORK-INFO.json` whose bytes do not change after
  verification

The two release directories are authenticated again after the final reapply.
Their complete authentication receipts must remain identical. The private
source repository and offline signing key are not inputs to this procedure.

The scenario file is trusted executable policy. Run only a reviewed scenario
on an isolated qualification host that contains no production wallet, release
signing key, or unrelated credentials. Commands are argument arrays and are
executed directly without a shell. The child environment is reduced to the
minimum host variables plus the authenticated release identities supplied by
the harness.

## Required sequence

The scenario must implement these seven commands:

1. `install_baseline`
2. `attempt_interrupted_candidate`
3. `apply_candidate`
4. `restart_candidate`
5. `rollback`
6. `reapply_candidate`
7. `probe_active`

The interrupted candidate command must return nonzero. Immediately afterward,
the probe must still identify a healthy baseline. The remaining probes must
identify, in order, candidate, candidate after restart, baseline after
rollback, and candidate after reapply.

`probe_active` writes one canonical JSON object to standard output with exactly
these fields:

```json
{"checksum_sha256":"<signed SHA256SUMS.txt digest>","commit":"<40 lowercase hex>","healthy":true,"network_id":"<64 lowercase hex>","network_name":"<network name>","schema":"CMFD_INSTALLED_RELEASE_PROBE_V1","version":"<SemVer>","virtual_genesis_hash":"<64 lowercase hex>"}
```

The scenario schema is `CMFD_UPDATE_ROLLBACK_SCENARIO_V1`. It contains exactly
`commands`, `platform`, `schema`, and `timeout_seconds`. Supported platform
labels are `windows-x86_64` and `linux-x86_64`, and the harness rejects a
scenario whose label does not match its x86-64 host. Commands may use these
placeholders:

- `{baseline_stage}`
- `{candidate_stage}`
- `{install_root}`
- `{python}`
- `{scenario_directory}`

The JSON must use canonical UTF-8 encoding with sorted keys, compact
separators, and one trailing newline.

## Invocation

Run this independently on clean Windows and Linux qualification hosts, using
two independently reproduced and signed release candidates:

```text
python scripts/update_rollback_qualification.py \
  --baseline-stage <authenticated-baseline-directory> \
  --candidate-stage <authenticated-candidate-directory> \
  --allowed-signers <trusted-allowed-signers> \
  --signer-identity <release-identity> \
  --ssh-keygen <trusted-ssh-keygen-path> \
  --scenario <reviewed-platform-scenario.json> \
  --install-root <new-empty-install-path> \
  --report <new-report-path>
```

The install root and report must not already exist, the report must be outside
the install root, and the install root must not overlap either release
directory. A report is created only after every step passes. Command output is
redirected to temporary files and is bounded to 1 MiB per stream before it is
hashed into the report.

## Acceptance boundary

The automated tests qualify the fail-closed harness and its state machine on
both CI operating systems. They do not substitute for the RCNet evidence run.
The RCNet gate closes only when the reviewed Windows and Linux package
scenarios have each run against two real, distinct, independently reproduced,
signed releases and their canonical reports have been retained with the
release evidence.
