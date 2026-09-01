# Exchange due-diligence answer sheet

Use this as an evidence index, not as preapproved legal or marketing copy.
Every answer must name its owner, date, evidence artifact, and approval status.

| Topic | Current technical answer | Required owner/evidence |
|---|---|---|
| Network status | Release-candidate integration work; not mainnet-ready | Release owner and signed network manifest |
| Asset/ticker | Common Foundry / CMFD | Project and venue collision approval |
| Units | 100,000,000 atoms per CMFD | Consensus emission specification |
| Supply | 657,000,249.98688 bootstrap CMFD plus perpetual 5 CMFD/block tail | Consensus test vectors and independent review |
| Distribution | Per-block 70/25/5 bootstrap; miner-only tail; no encoded up-front premine | Destination ownership disclosures; legal confirmation of no token sale |
| Deposit model | Immutable pseudonymous labels mapped to externally supplied x-only keys; durable added/removed event feed | Exchange custody architecture and confirmation policy |
| Withdrawal model | Prepared journal, threshold approvals, external anchors, provider-neutral signer responses | Exchange policy, approver roster, HSM design, rehearsal |
| Address format | Raw lowercase x-only-key hex; no checksum | Product decision and wallet-wide implementation |
| RPC transport | Loopback HTTP with separate Basic-auth scopes | Exchange-managed mTLS proxy and network controls |
| Audit | Internal review and audit candidate only | Named independent auditor and accepted final report |
| HSM | Protocol/reference signer only | Selected vendor, adapter, possession test, failover evidence |
| Reorgs | Explicit deposit removal events | Venue credit/reversal and deep-reorg policy |
| Upgrades | Fail-closed documented procedure | Packaged-host interrupted update and rollback evidence |
| Incident response | Repository procedure exists | Named 24/7 owners, secure channel, response objectives |
| Legal/regulatory | Not answered by source code | Authorized counsel and venue compliance team |
| Liquidity/market making | Not answered by integration software | Treasury/liquidity owner and written risk limits |

Do not submit placeholder, unaudited, or repository-derived legal answers as if
they were approved project representations.
