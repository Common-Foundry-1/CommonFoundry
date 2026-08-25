COMMON FOUNDRY STANDALONE CUDA MINER

1. Open your wallet's Receive page and copy its 64-character address.
2. Edit start-miner.sh and paste that address into PAYOUT_ADDRESS.
3. Run: chmod +x start-miner.sh && ./start-miner.sh
4. Leave GPU_INDEXES empty to use every supported NVIDIA GPU.
5. Leave the terminal open. Press Ctrl+C to stop cleanly.

The miner requests current work directly from the first reachable node. It does
not download or maintain another copy of the blockchain. The connected wallet
or node performs synchronization, builds templates, validates blocks, and
records accepted rewards for PAYOUT_ADDRESS.

To select specific cards, use a comma-separated list:
  GPU_INDEXES="0,1,2,3"

Supported native CUDA targets:
  Volta sm_70: V100, Titan V, Quadro GV100
  Turing sm_75: RTX 20 series
  Ampere sm_86: RTX 30 series
  Ada sm_89: RTX 40 series
  Blackwell sm_120: RTX 50 series

The miner automatically divides host preparation workers across selected GPUs,
up to 16 workers per GPU. Work ranges are separated so no worker in the rig
repeats another. Set WORKERS_PER_GPU to 1-16 to tune CPU/power use, or leave it
at 0 for the recommended automatic setting.

Every five seconds the miner prints rig and per-GPU hashrate, power draw,
hashes per watt, temperature, fan, utilization, clocks, VRAM use, uptime,
attempts, accepted blocks, and stale jobs. One H/s means one complete
ForgeMatrix nonce evaluation per second. Sensors that a card does not expose
show N/A and do not interrupt mining. Edit STATS_SECONDS in start-miner.sh to
change the reporting interval.

The miner first tries the local wallet at 127.0.0.1:18444, then the community
bootstrap. It pauses GPU work when neither node is reachable, rebuilds work when
the node tip changes, and reports a block only after a node acknowledges it.

Advanced operators who intentionally want a second full node can run
"cmfd-miner full-node --help". Normal mining should use start-miner.sh.
