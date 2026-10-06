# Common Foundry exchange integration guide

There are two ways to integrate. Most exchanges should use the first.

1. **The exchange wallet (recommended).** `cmfd-node exchange-wallet` is a
   wallet daemon that speaks Bitcoin Core's JSON-RPC: `getnewaddress`,
   `listsinceblock`, `gettransaction`, `sendtoaddress`, `walletpassphrase` and
   the rest. Point your existing Bitcoin integration at it. It keeps your keys
   on your server, reads the chain from the hosted endpoint (or your own node)
   and stores no chain. See [section 1](#1-the-exchange-wallet-recommended).
2. **Build transactions yourself.** Use the exchange JSON-RPC directly with
   offline key and signing tools. See [section 2](#2-building-transactions-yourself).

Both connect to the chain through one of:

- **Hosted endpoint:** a private HTTPS JSON-RPC endpoint run by Common Foundry,
  with credentials issued per exchange. No node to operate.
- **Own node:** `cmfd-node run --exchange-rpc-bind 127.0.0.1:<port>
  --exchange-rpc-auth-file <file>`, reachable on loopback only. See
  [START-HERE](START-HERE.md) and the [full integration guide](../docs/exchange-integration.md).

Keys never leave your systems in either setup: the endpoint and the node only
see public keys and signed transactions.

## Chain facts

| Item | Value |
|---|---|
| Unit | 1 CMFD = 100,000,000 atoms; the exchange RPC uses decimal atom strings, the exchange wallet CMFD numbers |
| Address | 64 lowercase hex characters: a BIP340 x-only public key (`destination_hex`); no checksum |
| Block target | 60 seconds |
| Coinbase maturity | 100 blocks (`spendable_height` = block height + 100) |
| Minimum fee | 0.1 CMFD (10,000,000 atoms) per transaction; the fee is burned |
| Transaction limits | 128 inputs, 128 outputs, 64 KiB encoded |

Because addresses carry no checksum, validate every customer withdrawal address
before accepting it: it must be 64 lowercase hex characters, and
`exchange-tx-sign` rejects anything that is not a valid public key.

## 1. The exchange wallet (recommended)

### Setup

Create a directory for the wallet and a `cmfd-wallet.conf` in it:

```ini
# Your integration authenticates to the wallet with these (HTTP Basic).
rpcuser=exchange
rpcpassword=<at least 16 random characters>
# Defaults: listen on 127.0.0.1:39120. To accept other hosts, set rpcbind and
# list every allowed address or network with rpcallowip.
#rpcbind=10.0.0.5
#rpcport=39120
#rpcallowip=10.0.0.0/8
# Where the wallet reads the chain: the hosted endpoint, or your own node's
# exchange RPC (http:// is allowed only to this machine).
upstream=https://sg-rpc.commonfoundry.ai/mainnet
upstreamuser=<your hosted endpoint user>
upstreampassword=<your hosted endpoint password>
```

Start it with the node binary from the signed release:

```sh
cmfd-node exchange-wallet --wallet-dir /var/lib/cmfd-wallet
```

On first start it creates `wallet.json` in that directory. **Back it up
straight away** (`backupwallet`, or copy the file). Every address the wallet
will ever hand out derives from it, so one backup is enough; you do not need a
new backup after `getnewaddress`. Encrypt it with `encryptwallet`, then call
`walletpassphrase` before sending, exactly as with bitcoind. Logs go to
`<wallet-dir>/logs`. Run one wallet process per `wallet.json`.

Use any Bitcoin Core client library or `bitcoin-cli`:

```sh
bitcoin-cli -rpcport=39120 -rpcuser=exchange -rpcpassword=… getnewaddress "user-123"
bitcoin-cli -rpcport=39120 -rpcuser=exchange -rpcpassword=… listsinceblock "<lastblock>" 60
bitcoin-cli -rpcport=39120 -rpcuser=exchange -rpcpassword=… walletpassphrase "<passphrase>" 60
bitcoin-cli -rpcport=39120 -rpcuser=exchange -rpcpassword=… sendtoaddress "<address>" 12.5
```

### Methods

JSON-RPC 1.0 and 2.0, batches and named parameters are supported, with Bitcoin
Core's error codes (-5 invalid address, -6 insufficient funds, -13 wallet
locked, -14 wrong passphrase, ...). Amounts are CMFD numbers with eight decimals.

| Group | Methods |
|---|---|
| Addresses | `getnewaddress`, `getrawchangeaddress`, `validateaddress`, `getaddressinfo`, `setlabel`, `getaddressesbylabel`, `listlabels` |
| Deposits | `listsinceblock`, `listtransactions`, `gettransaction`, `getreceivedbyaddress`, `listreceivedbyaddress`, `listunspent` |
| Balances | `getbalance`, `getbalances`, `getunconfirmedbalance`, `getwalletinfo` |
| Withdrawals | `sendtoaddress`, `sendmany`, `abandontransaction`, `settxfee`, `estimatesmartfee` |
| Security | `encryptwallet`, `walletpassphrase`, `walletlock`, `walletpassphrasechange`, `backupwallet` |
| Chain and status | `getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblock` (verbosity 1 or 2), `getrawtransaction`, `sendrawtransaction`, `getrawmempool`, `getnetworkinfo`, `getconnectioncount`, `getinfo`, `listwallets`, `uptime`, `ping`, `help`, `stop` |

Credit deposits after at least 60 confirmations, for example with
`listsinceblock "<lastblock>" 60` as with bitcoind.

### What differs from Bitcoin Core

- **Addresses** are 64 lowercase hex characters (an x-only public key) with no
  checksum. Check every customer withdrawal address with `validateaddress`.
- **Fees** are the network minimum, 0.1 CMFD per transaction, burned.
  `settxfee`, `fee_rate` and `conf_target` are accepted and ignored;
  `estimatesmartfee` returns 0.1.
- **Unconfirmed outputs cannot be spent**, so change comes back after one block
  (about a minute). The wallet splits change to keep at least 25 coins ready, so
  it can make many withdrawals per block. If every coin is waiting,
  `sendtoaddress` returns -6 and says to retry after the next block.
- **Incoming deposits appear once mined** (1 confirmation), not while in the
  mempool.
- **At most 128 inputs per transaction.** When the wallet holds more than 200
  coins (`consolidatethreshold` in the config; 0 turns it off), it merges the
  128 smallest into one, paying the 0.1 CMFD fee. Merges are not listed by
  `listtransactions`; `gettransaction` shows them.
- **Not available:** raw-transaction building (`createrawtransaction`,
  `signrawtransactionwithwallet`, `fundrawtransaction`), key import and export,
  message signing and multiple wallets.

### Monitoring and restore

`getblockchaininfo` reports `blocks` (the wallet's height) and `headers` (the
endpoint's); `getconnectioncount` is 1 while the endpoint answers, and
`warnings` explains any problem. The wallet keeps answering while the endpoint
is unreachable and catches up when it returns. Payments whose broadcast could
not be confirmed are kept and rebroadcast until they are mined.

To restore, put `wallet.json` and `cmfd-wallet.conf` into an empty directory
and start the wallet. It rescans from the block at which the wallet was created
(about 4 blocks per second from the hosted endpoint) and finds every address,
including ones handed out after the backup was taken.

## 2. Building transactions yourself

This is the lower-level route: you hold one key file per address, detect
deposits from an event stream and sign withdrawals with an offline tool.

### Keys and deposit addresses

Generate one key per customer deposit address, plus one or more hot-wallet keys,
with the node binary from the signed release. This runs offline:

```sh
cmfd-node exchange-key-new --output /secure/keys/customer-000123.key
# {"status":"created","key_file":"...","destination_hex":"9f0c…","warning":"…"}
cmfd-node exchange-key-show --key /secure/keys/customer-000123.key
```

The key file holds the 32-byte secret as 64 hex characters. It is created new
(never overwritten) and owner-only on Unix. It is the only copy of the secret:
back it up under your own key-management policy. Show customers the
`destination_hex`.

Keys can also be produced by any BIP340 implementation. The node accepts any
valid x-only public key as a destination.

### Detecting deposits

Register each deposit address once, then follow one event stream:

```json
{"jsonrpc":"2.0","id":1,"method":"registerwatchdestinations","params":[[
  {"label":"customer-000123","destination_hex":"9f0c…"},
  {"label":"customer-000124","destination_hex":"41aa…"}]]}
{"jsonrpc":"2.0","id":2,"method":"getdepositevents","params":["0",1000]}
```

- Batches hold 1–1,000 registrations and are atomic. Registrations are permanent
  and an exact retry is idempotent. Registering a fresh key is immediate; an
  address with history returns its past deposits as events.
- Labels are your identifiers, 1–128 visible ASCII bytes. On the hosted endpoint
  your labels are private to your credential (the limit is slightly lower; see
  `getexchangeinfo` → `hosted_endpoint.max_label_bytes`).
- Poll `getdepositevents` with the last `next_cursor` you stored, starting from
  `"0"`. Store the events and the new cursor in one database transaction. Pass
  `next_cursor` back unchanged; on the hosted endpoint cursors are endpoint-wide
  sequence numbers, so they increase but skip numbers that belong to other
  exchanges.
- `kind` is `deposit_added` or `deposit_removed`. A removal means a chain
  reorganization dropped the deposit; it names the original event in
  `added_cursor`. Reverse any credit you gave for it.

**When to credit.** An event carries `blockheight`. Compute confirmations as
`getblockcount − blockheight + 1` and credit a deposit only after at least 60
confirmations (about one hour). Coinbase deposits
(`"coinbase": true`) can only be spent once `getblockcount + 1 ≥ spendable_height`.

Without watch registration you can instead poll `getaddressbalance` /
`getaddressutxos` per address, but the event stream scales better and reports
reorganizations explicitly.

### Sweeping and withdrawals

Spend with `exchange-tx-sign`, then broadcast the hex it prints.

1. List spendable outputs of the paying keys:
   `{"method":"getaddressutxos","params":["<hot destination_hex>",1000]}`.
   It returns only confirmed, mature outputs that no transaction in the node's
   mempool is already spending.
2. Write a request. Each input names the output, its owner and the key file;
   outputs are the payments; any remainder goes to `change_destination_hex`:

   ```json
   {
     "network_id": "88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62",
     "inputs": [
       {"txid": "…", "vout": 0, "value_atoms": "250000000000",
        "destination_hex": "<hot destination_hex>", "key_file": "/secure/keys/hot-1.key"}
     ],
     "outputs": [
       {"destination_hex": "<customer withdrawal address>", "value_atoms": "1500000000"}
     ],
     "change_destination_hex": "<hot destination_hex>",
     "fee_atoms": "10000000"
   }
   ```

3. `cmfd-node exchange-tx-sign --request withdrawal-42.json` prints
   `txid`, `transaction_hex`, `input_atoms`, `output_atoms`, `change_atoms` and
   `fee_atoms`. It runs offline and refuses a key that does not own its input, a
   fee below 0.1 CMFD, a request for another network, duplicated inputs, and any
   leftover without a change destination, so a typo cannot silently burn
   funds as fee.
4. Record the `txid` and `transaction_hex` against the withdrawal **before**
   broadcasting, then submit:
   `{"method":"sendrawtransaction","params":["<transaction_hex>"]}`.
5. Track it with `gettransaction [txid]`: `status` moves from `mempool` to
   `confirmed` and `confirmations` counts up.

A sweep is the same request with many deposit-key inputs (up to 128) and one
output to the hot wallet.

**Never sign a second transaction for the same withdrawal** while the first
could still confirm. To retry, resubmit the identical `transaction_hex`. It is
safe to send again:

| Result | Meaning |
|---|---|
| txid returned | accepted (or already in the mempool) |
| `transaction_already_confirmed` | already mined; nothing to do |
| `mempool_unconfirmed_input` | an input is no longer unspent: check `gettransaction`; if the transaction is not found, the input was spent by something else |
| `mempool_input_conflict` | another transaction in the mempool spends the same input |
| `mempool_fee_too_low` | fee below the minimum |

### Reading the chain

`getblockcount`, `getbestblockhash`, `getblockhash [height]`,
`getblock [hash, 1|2]`, `getrawtransaction [txid, verbose]`,
`gettransaction [txid]`, `getaddressbalance [destination_hex]`,
`getaddressutxos [destination_hex, limit, cursor]`, `getrawmempool`. Transaction
lookups do not need a block hash. Parameters are positional; batches and named
parameters are not supported.

### Errors and retries

Every error carries `error.data.code` and `error.data.retryable`. Retry only
when `retryable` is true, and never let a timeout trigger a new withdrawal
transaction: look the txid up first. The machine-readable catalog is
[errors.json](errors.json). On the hosted endpoint, `upstream_busy` (retryable)
means the node was momentarily at capacity.

## 3. Hosted endpoint specifics

| Item | Value |
|---|---|
| Transport | HTTPS, `POST` JSON-RPC 2.0, HTTP Basic credentials issued per exchange |
| Rate limit | 5 requests/second (burst 20) and 8 connections per IP |
| `getblock` | verbosity 1 or 2 only |
| Not available | withdrawal-custody methods (use `exchange-tx-sign` + `sendrawtransaction`) |
| Isolation | watches and deposit events are visible only to your credential |

`getexchangeinfo` reports the methods available to you and a `hosted_endpoint`
object with your client name and label limit.
