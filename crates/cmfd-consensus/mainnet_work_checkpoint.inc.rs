// Mainnet work checkpoint. Until the release cut fills it, this is `None` and
// the network has no work rule. A later build that moves the checkpoint forward
// (for example a wallet and miner package cut later) exports again at its own
// height and replaces all three fields.
//
// Export the list from a stopped full node that tracks the canonical chain, or
// from a copy of its data directory (the export opens the data directory
// exclusively), with C at least 100 blocks below the tip:
//   cmfd-node work-checkpoint export --height C --out mainnet-work-checkpoint-v1.ids
// Cross-check the printed checkpoint_block_id and ids_blake3 against a second
// independent full node, place the file at crates/cmfd-consensus/data/mainnet-work-checkpoint-v1.ids
// and replace `None` with (the include path is relative to this file):
//   Some(WorkCheckpointPin {
//       height: C,
//       block_id: [/* checkpoint_block_id printed by the export */],
//       ids: include_bytes!("data/mainnet-work-checkpoint-v1.ids"),
//       ids_blake3: [/* ids_blake3 printed by the export */],
//   })
// The cmfd-node build gate refuses a production-mainnet build while this is `None`.
None
