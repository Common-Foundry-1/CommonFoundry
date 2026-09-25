# Mainnet seed transport readiness - September 25 UTC

The planned seed endpoint `173.249.35.251:29444` passed bounded external TCP
round trips from the Windows workstation and AI01. This qualifies the network
route and prepared firewall rule, not a mainnet protocol handshake or launch.

## Prepared and verified

- Added only the IPv4 rule allowing TCP 29444 to the seed's confirmed
  `173.249.35.251` interface, labelled `CMFD-mainnet-P2P`. Existing SSH limits,
  RC peer rules and IPv6 rules were preserved. No RPC rule was added.
- The test listener ran as the existing unprivileged `commonfoundry-mainnet`
  account with read-only filesystem protection, no GPU devices or credentials,
  bounded message lengths/timeouts and a 70-second service lifetime limit.
- Both clients exchanged the fresh diagnostic nonce, and the seed recorded
  both matching connections. These were two hosts behind the same external
  WAN address, not two independent Internet networks.
- An external connection attempt to mainnet RPC port 29443 did not connect.
  The signed seed unit continues to bind RPC only to localhost.
- The diagnostic process exited successfully. Its transient unit was removed,
  and subsequent `ss -lnt` showed no listener on 29444. The firewall rule remains
  prepared for the future node; the mainnet service remains disabled/inactive.
- The RC seed retained PID 937, the explorer tunnel PID 939 and AI01's RC pool
  PID 7669, all with zero restarts. The mainnet seed data directory remained
  empty. No node, wallet, mining worker or mainnet transaction was started.
- The VPS clock reported synchronized. The upgraded filesystem had
  1,221,677,043,712 bytes free at the pre-check.

## Evidence

- `PEER-FIREWALL-PREPARED.json`: SHA-256
  `af812a57de456232d791590517165b5f62cc24855368cace9ad07e2b1a8eff23`.
- `SEED-EXTERNAL-TCP-1.json`: SHA-256
  `97f15b0ba58035040a3194c83fe78922c2fcb660f2571fc8689994b278d51baf`.

The diagnostic deliberately used a small echo exchange, not the blockchain
protocol or an early launch-beacon substitute. Pool inbound TLS/NAT routing,
actual mainnet peer discovery and synchronization, and transaction/block/payout
checks remain separate. Source/package publication stays October 2, and mining
October 3, at noon America/Chicago (17:00 UTC).
