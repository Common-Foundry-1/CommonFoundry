# Common Foundry exchange operations pack

Status: deployment candidate, not production approval.

This directory turns the exchange RPC and custody references into an operator
handoff. It does not replace an exchange's own custody review, independent
audit, HSM qualification, legal review, or launch authorization.

## Deployment sequence

1. Build the exact candidate and save `cmfd-node network-info` beside its
   release checksum and source commit. Never reuse a data directory, keyring,
   policy, or anchor from another network identity.
2. Provision a dedicated service identity and three disjoint authorities:
   integration RPC authentication, withdrawal RPC authentication, and custody
   secrets/anchors. Keep the external anchors beyond the node service's write
   authority.
3. Render either the Linux or Windows template with absolute paths. Keep the
   node RPC on a numeric loopback address. If remote access is necessary, put
   a separately managed mTLS proxy in front of loopback and retain Basic-auth
   scope separation behind it.
   Because plain loopback HTTP does not authenticate the server to the client,
   also qualify service/port ownership and local ACL isolation; public chain
   identity fields are not proof of local process identity.
4. Run the existing ACL qualification against the installed paths and service
   identity. A template review or fixture result is not host qualification.
5. Run `scripts/exchange_conformance.py live` from a source checkout, or
   `tools/exchange_conformance.py live` from the packaged kit, with independently
   pinned network and consensus identities. Store its create-new evidence
   outside the node's writable directory. The companion
   `exchange_coordinator.py` is a process-restart-safe poll/ack reference, not
   a physical power-loss-qualified store or customer crediting engine.
6. Exercise deposit additions/removals, withdrawal release/cancel/restart,
   backup restore, interrupted upgrade, and physical power loss on disposable
   representative hardware. Record exact binaries, host identity, and hashes.
7. Obtain independent audit acceptance and the exchange's written production
   approval before enabling value-bearing deposits or withdrawals.

## Files

- `linux/commonfoundry-exchange.service.in`: systemd service template.
- `proxy/nginx-mtls.conf.in`: optional mTLS boundary template.
- `windows/Start-CommonFoundryExchange.ps1`: foreground launcher suitable for
  an exchange-approved Windows service supervisor.
- `backup-recovery.md`: backup, restore, and disaster-recovery gates.
- `upgrade-rollback.md`: fail-closed candidate upgrade sequence.
- `readiness-gates.json`: machine-readable, deliberately conservative status.
- `diligence/`: factual exchange questionnaire and contact templates.

Every placeholder beginning with `@@` must be replaced. These files are not a
claim that the rendered host has passed ACL, recovery, or power-loss testing.
