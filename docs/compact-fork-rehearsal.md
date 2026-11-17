# Isolated mainnet-height fork rehearsal

The opt-in Linux test module `crates/cmfd-node/src/compact_fork_rehearsal.rs`
exercises the actual activation at 67,535. It requires a separate network
namespace with only loopback, explicit configuration, and a new disposable
directory under the local rehearsal workspace. Normal release binaries contain
none of its bootstrap or control commands.

Its starting point is a **synthetic trusted pruned checkpoint at 67,533**, with
disposable encrypted wallet keys and test balances. It is not an authenticated
replay of historical mainnet. Blocks produced above that checkpoint pass normal
mainnet target, complete proof, transaction and block admission. CPU validators
check the pre-activation work independently of the proving GPU.

The local controller records separate-process P2P synchronization across the
activation, TLS reference-miner shares, a payout and a heavier competing branch.
It then checks payout reconciliation, wallet RPC sending, identical canonical
state, cold restart, pruning and recovery from a stopped pre-upgrade backup.
The rehearsal uses a test-only retention of two blocks and a snapshot interval
of one; production minimum retention remains 288 blocks. Restoring a backup
after activation uses upgraded software and a peer retaining the needed blocks.
It does not establish that old software can follow the fork.

The controller must preserve its event log, final result, failure attempts,
component identities and process/GPU cleanup report. A successful run is runtime
qualification evidence, not independent cryptographic review or authorization
to deploy a stable release. Public peers, installed wallets, operator keys and
live pool ledgers are outside this rehearsal.
