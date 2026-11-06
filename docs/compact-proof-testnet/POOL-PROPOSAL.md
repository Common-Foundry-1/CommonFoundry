# More room, faster relay: join the Common Foundry compact-proof testnet

Common Foundry has started a dedicated testnet for a smaller, self-contained ForgeMatrix block proof. Our local pool has already mined **three fresh compact-proof blocks**; two independent nodes accepted them, one caught up after a restart, and the optimized pool and node builds now interoperate. We would love pool operators to join the next phase and help measure this improvement under real mining traffic.

## Why this is exciting

Our current block proof is 12.03 MB. The direct proof prototype produced and independently verified complete packets around **5.5 MB** on a 16 GB GPU. The new testnet's first three fresh blocks each carried a packet around **5.66–5.67 MB**: roughly **53% fewer raw proof bytes** than today's format. Two earlier proof samples showed about **35% less compressed proof traffic**. Because the existing **16 MiB block limit includes the proof**, the smaller packet can also free roughly **6.4 MB** for transactions in a byte-limited block.

The testnet keeps the ForgeMatrix workload and existing field, hash, and BaseFold proof parameters. It gives us a chance to measure the full benefit in the places pools feel it: winning-block latency, stale blocks, propagation, relay traffic, and new-node catch-up. Every participating pool helps turn a promising compact proof into a well-tested network upgrade.

## What participating pools can test

- Run a separate testnet pool and GPU proof worker with dedicated testnet data and payout addresses. Pools with 16 GB cards can assign share replay and full proving to separate GPUs.
- Submit ordinary shares and winning blocks; confirm that independent nodes accept the same proofs and reject altered packets.
- Compare block propagation, stale rates, sync bandwidth, proof latency, and GPU memory with the current format.
- Exercise restarts, stale jobs, mixed GPU models, and multiple miners against the pool.
- Share practical feedback on setup, logs, reliability, and where the smaller proof makes the biggest difference.

We will provide the pinned network identity, test binaries with checksums, pool configuration, connection details, and a short verification guide as the operator kit is qualified. Testnet coins have no monetary value. Mainnet keeps its existing proof rules while the testnet gathers evidence.

## Path to a release decision

The optimized local pilot has a useful starting measurement: **4.28 seconds for its GPU proof stage and 16.75 seconds for the complete winning-share-to-block path**. Pool canaries will help us sharpen that full path while measuring propagation, sync bandwidth, GPU memory, and stale rates. We will publish those results for pool operators to review before any versioned mainnet upgrade is proposed.

**Interested in joining?** Tell us which pool software and GPU mix you operate. The local pool and nodes already interoperate end to end; we will send the operator kit and connection details for the public canary.
