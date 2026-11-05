---
name: cmfd-mining-setup
description: Plan and check a Common Foundry (CMFD) GPU miner setup using current signed packages and hardware requirements. Use for first-time CMFD mining, solo versus pool setup, GPU compatibility questions, or checking whether mining work is accepted.
---

# Set up CMFD mining

Read the maintained [mining guide](https://commonfoundry.ai/learn/mining/) and the chosen release's miner instructions from the [full release list](https://github.com/Common-Foundry-1/CommonFoundry/releases). Use the release-verification skill or that release's verification procedure before running downloaded software.

## Establish the setup

Collect the exact GPU model and VRAM, driver, OS, available RAM and disk, intended solo or pool mode, and whether the machine already hosts a renter or other workload. Use existing context first. Confirm hardware qualification for that exact miner version. A pool share test and a full block-winning proof test establish different things; a working small-memory share path does not establish full proof capability. Ordinary wallets and nodes do not need a mining GPU.

CMFD mining performs ForgeMatrix work to compete for blocks. It does not execute a paid customer's inference request. Model inputs are approximately 6.4 GB; some solo paths need substantially larger prepared files. Check current release requirements before estimating space or starting preparation. Do not infer support for every GPU from one measured result.

## Configure the requested mode

- **Solo:** follow the current package's node connectivity, mainnet identity, payout-address, and proof preparation instructions. Keep accepted and validated heights distinct when assessing node readiness. Do not invent command flags from an older version.
- **Pool:** obtain the current endpoint, port, miner version, worker format, fee rules, and payout terms from the selected pool operator. Pool operation and availability are independent of the protocol. Confirm the payout address with the user; never replace it with an example address.

Use the authorization already provided for the setup. Before starting compute, check that the selected GPU is available and that the command targets the intended configuration. Preserve active renter workloads and existing miner configurations; stage changes where possible. A request to assess compatibility alone does not authorize starting a miner.

## Check the result

Record the package version, exact hardware and driver, selected mode, observation interval, rejected/error counts, and evidence of accepted work. For pools, separate accepted shares from confirmed payouts. For solo mining, separate attempted work from a network-accepted block. Use the [explorer](https://explorer.commonfoundry.ai/) and the relevant pool dashboard to corroborate results; local logs alone do not establish a payout.

Include electricity, pool fees, hardware wear, and current network competition when discussing costs. Report measured performance with its test conditions and uncertainty. Do not promise earnings or treat a short successful run as full production qualification.
