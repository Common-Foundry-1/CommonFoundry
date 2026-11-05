---
name: cmfd-node-troubleshooting
description: Diagnose Common Foundry (CMFD) node or wallet synchronization using heights, peers, release identity, logs, and storage checks. Use for a stuck CMFD sync, a wallet behind the explorer, repeated catch-up failures, or uncertainty about a pending transaction.
---

# Diagnose CMFD node and wallet synchronization

Establish the installed version, OS, service/process, data directory, and symptom. Read the matching release's user guide and notes from the [release list](https://github.com/Common-Foundry-1/CommonFoundry/releases). Begin with read-only checks; use the user's existing authorization for any repair.

## Collect evidence

1. Record local accepted height, validated height, tip, peer count, and timestamps from the node's supported status output or logs. Repeat after an appropriate observation interval. Advancing accepted blocks and slower validated blocks can indicate ongoing catch-up; a single unchanged wallet display is insufficient to diagnose a stall.
2. Compare with the public [explorer snapshot](https://explorer.commonfoundry.ai/v1/explorer), or `get_network_status` at [the public MCP endpoint](https://commonfoundry.ai/docs/mcp/). Record the source and fetch time. The expected mainnet ID is `88296bc39c10e8bc1dd4818d4d42412fe5f08210651110377f495da299812f62`, with proof profile `ProductionV4`. Public snapshots can lag or change after a reorganization; they are observations, not independently verified proofs.
3. Check free space on the actual chain-data volume, write/permission errors, peer connectivity, process health, and repeated validation failures. Inspect recent relevant log lines, with private paths and access-bearing URLs redacted before sharing. A full data volume can prevent replay or persistence even while the process is running.
4. For a pending transaction, obtain its transaction ID from existing records and check confirmed chain evidence. A stale wallet can retain a pending display after confirmation. Do not resend value merely because the display has not refreshed. Keep seeds, private keys, recovery codes, and passphrases out of diagnostics.

## Choose the smallest justified repair

Explain which observation supports the diagnosis. Resolve storage or connectivity causes first. Before an authorized update, verify the signed package. Before a restart or data-path change, identify the correct process and preserve the wallet backup, chain data, and unrelated services or renter workloads. Do not delete the chain directory or force a rescan as a generic first step. Disk cleanup should target reviewed disposable files, not wallet or chain state.

Recheck local accepted and validated height progression, peers, errors, and available space after the repair. Report observed recovery separately from full synchronization. If unresolved, provide the version, network ID, timed height samples, storage state, and minimal redacted error excerpt for [community support](https://discord.gg/XGuutqWMWP), without claiming a consensus failure from a wallet UI symptom.
