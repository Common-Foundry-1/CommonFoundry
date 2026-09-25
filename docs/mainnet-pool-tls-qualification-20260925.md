# Staged mainnet pool TLS qualification - September 25 UTC

The staged AI01 mainnet certificate/key pair passed a native TLS 1.3 handshake
using the pool's existing certificate-pin verifier and TLS configuration builders.
This is a transport-identity check, not a mainnet launch or public pool endpoint.

## Evidence

- Certificate SHA-256:
  `0a896a857857354781f06fe5b9ca05e632a35eab915b9cfd68545905bd1300d2`.
- The verifier and client/server configuration source match the signed
  `a8b23ec66a5a9f42bd2821408b6b9a886cffd392` baseline without production changes;
  normalized source-fragment SHA-256:
  `c77b323cca3326919a69b378c061a34f4b24b96221ef86d5b7da63acea5c9b12`.
- `Cargo.lock` is unchanged. The harness uses rustls 0.23.45 and its explicit
  ring provider, with the production TLS-1.3-only configuration.
- The generated-identity regression passed on Windows MSVC and Linux. Correct
  pin acceptance, wrong-pin rejection, mismatched-key rejection and malformed
  certificate/key rejection are covered.
- The deployed identity passed the same cases as the unprivileged
  `commonfoundry-mainnet-pool` account in an ephemeral systemd unit. The harness
  verified a different network namespace and absence of NVIDIA devices. It used
  only loopback sockets and systemd credential files; no key was copied off AI01.
- RC pool PID 7669 remained active with zero restarts. Mainnet remained
  disabled/inactive. Temporary credential mounts were removed after completion.
- Retained receipt `AI01-TLS-HANDSHAKE-QUALIFIED.json` has SHA-256
  `6ef4bd30eb61364726f37f4d3554ade91304aa0091537c95b847272438cf2581`.
- Exact Linux test executable SHA-256:
  `3f6db897f77abfa9f919c660525149e3935533dd8f101d271e456131466d7b6e`.
  This is a test harness, not a replacement signed release binary.

## Repeatable regression

```text
cargo test --locked -p cmfd-node --lib \
  pool::tests::isolated_pool_tls_identity_accepts_correct_pin_and_rejects_mutations \
  -- --exact
```

The separate ignored operator test requires explicit absolute regular-file paths
in `CMFD_POOL_TLS_CERT_PATH` and `CMFD_POOL_TLS_KEY_PATH`, plus the exact lowercase
public fingerprint in `CMFD_POOL_TLS_EXPECTED_PIN`. Invoke only its exact test
name with `--ignored --exact`; do not run all ignored tests on an operator host.
For a real deployment identity, use a temporary unprivileged systemd unit with
`PrivateNetwork=yes`, `PrivateDevices=yes`, read-only filesystem protection and
`LoadCredential`. Keep credential bytes out of shell arguments, environment
values, logs and reports. The environment contains paths and the public pin only.

The first Windows fixture failed because it left accepted sockets nonblocking.
Winsock inherits listener properties on accepted sockets; the production
`handle_connection` already resets blocking mode. The fixture now does the same,
uses bounded I/O/accept waits, joins its thread, and coordinates closing after
the client receives the response. No production networking behavior was changed.
See [Microsoft's accept documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept).

## Not established by this check

Public NAT/firewall reachability, the actual signed daemon's external endpoint,
pool job/share exchange, GPU correctness, block production and payouts still
require their own qualification. Source/package publication remains October 2,
and mining October 3, at noon America/Chicago (17:00 UTC). This test opened no
public port and started no node, wallet or mining process.
