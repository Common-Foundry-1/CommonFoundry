# Mainnet pool credential compatibility - September 25, 2026

The Linux pool service now normalizes systemd-delivered credentials into its
private runtime directory before starting the launcher. This fixes a real
startup failure on systemd versions that use POSIX ACLs for service credentials.
It does not change wallet cryptography, passphrases, launch authorization or
proof-of-work rules.

## Reproduced failure

On the Ubuntu VPS running systemd 255, `LoadCredential` exposed the synthetic
passphrase with mode `0440`, owned by root, with a named-user read ACL. The native
wallet reader correctly rejected its group-mask bits because wallet passphrase
files must be `0600` or stricter. The previous pool launcher passed this path
straight to the node. The seed-node template already used a private runtime copy.

The test used the actual Linux node built from
`363a3c8b70ac1cdd65d92c9ba0ab91422068e5f0`, SHA-256
`970ffee215787a94b343d27992b84668a2a5697b23702b4e9134a47653c2d1a3`.
The only passphrase and key inputs were explicitly synthetic test fixtures.

## Implemented correction

- Preserve root-only input files and systemd `LoadCredential`.
- Before the pool launcher, use `install --mode=0600` for the passphrase and TLS
  key into `/run/commonfoundry-mainnet-pool`, owned by the service and mode `0700`.
- Require that exact `RUNTIME_DIRECTORY` in the launcher. Reject redirected or
  symlink runtime directories, inappropriate ownership, group/world-accessible
  copies and non-regular or multiply linked credential files.
- Pass only the normalized file paths to the node. Do not put secret contents
  into arguments or environment variables. Keep the native wallet permission
  policy unchanged.
- Let systemd remove the temporary runtime directory when the service stops.
  Original credentials remain in the protected configuration directory.

## Evidence and limits

A bounded, unprivileged, network-isolated and GPU-isolated systemd test reproduced
the old permission rejection and executed the exact two new copy commands from
the pool template, with test-only paths substituted. The copies were mode `0600`
and owned by the test service. The revised pool credential preflight accepted
them. The native reader then passed the credential-permission boundary and
rejected the deliberately invalid backup at backup validation, as expected.
No wallet, chain, real credential or mining operation was created or opened.
Systemd removed the test runtime directory after completion.

This was not an actual mainnet pool start, valid-wallet restore, future-beacon
test, or final signed-package qualification. The running RC seed and pool were
not interrupted or upgraded. Final packages must contain both the revised unit
and matching launcher; this does not approve an old package with a new unit.

Regression results:

- Linux pool-service suite: all 16 tests passed, including Unix modes/symlinks.
- Windows pool-service suite: 14 passed, two Unix-specific tests skipped.
- Windows mainnet package suite: all 24 fixture tests passed.

Source/plan review, final package assembly and hardware qualification remain
separate requirements. No release signature or mainnet activation is implied.
