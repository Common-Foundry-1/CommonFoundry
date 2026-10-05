# Transaction and address queries for exchange integrations

These additive methods extend `chain-preview-v0.4`. They read the active chain
and this node's mempool. They do not use the node wallet or sign transactions.
Parameters are positional and requests use JSON-RPC 2.0 with an explicit id.

## Transaction lookup

| Method | Parameters | Result |
|---|---|---|
| `getrawtransaction` | `[txid, verbose=false, optional_blockhash]` | Canonical transaction hex, or a decoded object when verbose is true or 1 |
| `gettransaction` | `[txid, optional_blockhash]` | Decoded chain/mempool object, independent of wallet ownership |

`txid` and `blockhash` are 64 hexadecimal characters. `verbose` accepts a
boolean or integer 0/1. A lookup without a block hint searches the full retained
active chain and local mempool, including spent transactions. There is no
4,096-block lookback cutoff. The node's full-history transaction index locates
the block, and coinbase identifiers are derived from active block identities,
so a lookup reads only the one block that holds the transaction; each result
authenticates its durable block record. The coinbase index holds up to
5,000,000 active blocks; an explicit block hash bypasses it at that limit.

Decoded results include canonical `hex`, inputs (`vin`), outputs (`vout`),
`blockhash`, `blockheight`, `confirmations`, `active`, `status`, `bestblock`, and
the observed tip `height`. Confirmations are 0 for local mempool transactions,
positive for the active chain, and -1 for a stored inactive block selected by
an explicit hint. `bestblock` and `height` bind the observation to a chain tip.
Results are observations, not a finality guarantee. Reorganization removes
detached transaction locations before the replacement branch is indexed.

Coinbase identifiers are Common Foundry's block-qualified
`coinbase_outpoint_id`, also returned by `getblock`. Coinbase is a component of
the block, so it has no standalone transaction frame. Its verbose object has
`coinbase:true`, `hex:null`, empty `vin`, and its outputs. A raw, nonverbose
coinbase request returns `invalid_params`; it never invents broadcastable bytes.

Example:

```json
{"jsonrpc":"2.0","id":1,"method":"getrawtransaction","params":["<64-character-txid>",true]}
```

Unknown identifiers return JSON-RPC -5 with `transaction_not_found`.
Malformed parameters return -32602 / `invalid_params`. A chain change during
the off-lock read returns -32020 / `transaction_query_chain_changed`, marked
retryable for the read. Capacity returns -32021 / `transaction_query_capacity`.
Storage corruption is reported and faults the node's storage health.

## Address balance

`getaddressbalance [destination_hex]` and `getbalance [destination_hex]` are
aliases returning the same structured object. A destination is a valid x-only
secp256k1 public key encoded as 64 hexadecimal characters. The argument is
required; it is never a wallet account name, label, or implicit node wallet.

All amounts are decimal **atom strings**. One CMFD is 100,000,000 atoms.
The response includes:

| Field | Meaning |
|---|---|
| `balance_atoms`, `confirmed_atoms` | All active-chain unspent key outputs for the destination, including immature outputs |
| `spendable_atoms` | Confirmed outputs mature at the next block height |
| `immature_atoms` | Confirmed outputs that are not yet mature |
| `available_atoms` | Mature outputs excluding inputs spent by local mempool transactions and exchange withdrawal reservations |
| `pending_incoming_atoms` | Outputs to this destination in this node's mempool |
| `pending_outgoing_atoms` | Confirmed inputs consumed by this node's mempool |
| `unconfirmed_delta_atoms` | Signed decimal difference between pending incoming and outgoing; includes change and fee effects |
| `utxo_count` | Number of confirmed unspent key outputs |
| `bestblock`, `height`, `network_id` | Chain observation and network binding |
| `mempool_scope` | `this_node_only`; unconfirmed state can differ between peers |

Confirmed balance does not subtract pending spends. `available_atoms` does,
and excludes pending incoming outputs. The query does not count inference
channel locks as key address balances. It never returns node wallet keys.

## Spendable outputs

`getaddressutxos [destination_hex, limit=1000, cursor=null]` returns the confirmed
key outputs currently available to spend at the next block height. The address
format is the same as `getaddressbalance`. Immature outputs, inputs spent by
local mempool transactions, and withdrawal reservations are excluded. Pending
incoming outputs are not included. Calling this method does not reserve coins.

```json
{"jsonrpc":"2.0","id":1,"method":"getaddressutxos","params":["<64-character-destination-public-key>"]}
```

The `utxos` array contains `txid`, `vout`, `value_atoms`, `spendable_height`,
`lock_type` (`key`), and `destination_hex`. Use `txid` and `vout` for transaction
inputs, and read `value_atoms` as a decimal integer string. Amounts use the same
atom unit as balances. Outputs are sorted by txid bytes, then output index.

The response also includes `network_id`, `bestblock`, `height`, `snapshot`,
`total_utxos`, `returned_utxos`, `available_atoms`, `has_more`, `next_cursor`, and
`mempool_scope`. `available_atoms` is the sum across all available outputs,
including pages not yet returned. It equals `getbalance.available_atoms` when
both calls observe the same chain and local pending/reservation state.

`limit` must be from 1 to 1,000. When `has_more` is true, pass the returned
`next_cursor` object as the third parameter to get the next page. The cursor
contains `snapshot`, `txid`, and `vout`; pass it unchanged. An empty address
returns an empty array, zero total/amount, `has_more:false`, and `next_cursor:null`.

If the chain tip or available outputs change between pages, the method returns
-32022 / `utxo_snapshot_changed`. Discard those pages and start again without a
cursor. Invalid parameters or a cursor outpoint absent from an otherwise
matching snapshot return -32602 / `invalid_params`. A listing is an observation;
transaction submission still checks that its inputs remain spendable.

## Restricted remote deployment

The native exchange listener remains loopback-only and Basic authenticated.
A remote deployment terminates HTTPS at a proxy and permits only chain reads,
these address/transaction queries, mempool reads, and `sendrawtransaction`.
The Singapore RCNet deployment uses `https://13.140.66.6/rpc`, with a trusted
IP-address certificate and automatic renewal. Integration credentials are
handed over separately from the endpoint and API documentation.

`sendrawtransaction [canonical_signed_transaction_hex]` validates and broadcasts
already signed Common Foundry wire bytes. Bitcoin transaction serialization
is not supported. Signing, custody, watch registration, wallet controls, and
native RPC paths are excluded from the remote gateway. Neither the gateway
nor proxy automatically retries a broadcast. After an ambiguous response,
look up the txid before deciding to submit again.

This endpoint serves RCNet-1 rehearsal coins. Mainnet deployment and exchange
custody readiness are separate qualifications.
