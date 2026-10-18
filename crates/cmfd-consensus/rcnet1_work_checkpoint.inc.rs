// RCNet-1 work checkpoint. It must be filled before RCNet-1 nodes are deployed
// with the work rule; until then it is `None` and the network has no work rule.
//
// Export the list from a stopped full node that tracks the canonical chain, or
// from a copy of its data directory (the export opens the data directory
// exclusively), with C at least 100 blocks below the tip:
//   cmfd-node work-checkpoint export --height C --out rcnet1-work-checkpoint-v1.ids
// Cross-check the printed checkpoint_block_id and ids_blake3 against a second
// independent full node, place the file at crates/cmfd-consensus/data/rcnet1-work-checkpoint-v1.ids
// and replace `None` with (the include path is relative to this file):
//   Some(WorkCheckpointPin {
//       height: C,
//       block_id: [/* checkpoint_block_id printed by the export */],
//       ids: include_bytes!("data/rcnet1-work-checkpoint-v1.ids"),
//       ids_blake3: [/* ids_blake3 printed by the export */],
//   })
// The cmfd-node build gate refuses a production-rc build while this is `None`.
None
