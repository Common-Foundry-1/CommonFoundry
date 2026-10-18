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
Some(WorkCheckpointPin {
    height: 2227,
    block_id: [
        0x8f, 0xec, 0x8a, 0xeb, 0x2d, 0x74, 0x18, 0xba, 0x0d, 0xcc, 0x87, 0x2b, 0xa1, 0xbc, 0x65,
        0xcc, 0xec, 0x17, 0x33, 0x75, 0x47, 0x13, 0x3e, 0xc3, 0xd4, 0xb9, 0x3e, 0xfb, 0x5e, 0x38,
        0x72, 0x51,
    ],
    ids: include_bytes!("data/rcnet1-work-checkpoint-v1.ids"),
    ids_blake3: [
        0xb5, 0x66, 0x0a, 0x7b, 0x0e, 0x55, 0xa2, 0x78, 0xb2, 0x6a, 0x6a, 0x54, 0x6a, 0x7f, 0xfe,
        0xe1, 0x83, 0x24, 0x15, 0x8e, 0x66, 0xaa, 0x35, 0x9b, 0xe2, 0x4a, 0xfc, 0x9a, 0xce, 0x42,
        0x2c, 0x5d,
    ],
})
