# Compact Proof Testnet-1 public canary

This network lets pool operators, GPU miners and independent node testers exercise the complete compact proof verifier. Ordinary nodes use proof-only validation; the dedicated seed also replays ForgeMatrix work as an independent audit.

| Setting | Public canary |
| --- | --- |
| Network ID | `8a34c0d9eaa92c5eaec4af7fe146afdfa2ab6859918b7deb0c97e0a1f600d6d1` |
| Virtual genesis | `b8f98ab6a9c003da3695ce300f49cb3b59a2245e723ddc78c5af95cc8af78254` |
| Genesis timestamp | 2026-11-06 00:00 UTC |
| Initial target | `01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| Target spacing | 60 seconds, using the existing chain difficulty adjustment |
| Public seed | `209.145.48.36:23444` |
| Seed backend | Dedicated unprivileged Proxmox container 1202; St. Louis provides TCP transport only |
| RPC | Loopback port 23443 |
| Reference pool | Port 23445; each operator publishes its own pinned miner URL |
| Proof | Version 2, self-contained `CMFDDR02`, under 6 MB |
| Node validation | Complete compact proof and normal block rules; ordinary nodes do not rerun matrix mining work |
| Audit node | The Proxmox seed also replays work for comparison during this canary |
| Storage identity | `commonfoundry-compact-public-testnet1` |

The Linux package includes the reference pool/node, miner, replay worker, compact prover, verified input downloader, address helper, and diagnostics collector. The pool and miner use Common Foundry's pinned TLS pool protocol. The packaged README contains exact launch commands and hardware/input requirements.

This public network has a separate identity from the loopback pilot recorded in LOCAL-PILOT-RESULTS.md. Its initial difficulty and share target support real mining trials. Testnet v0.3.0 keeps the network identity, genesis and proof format of v0.1/v0.2; operators can upgrade with their existing chain and inputs. The latest local pool path averaged 5.74 seconds with 5.65–5.69 MB proofs. The proof-only policy applies to ordinary nodes, while the seed continues its independent audit replay. Test coins have no monetary value.
