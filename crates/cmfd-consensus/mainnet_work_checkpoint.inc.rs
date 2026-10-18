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
Some(WorkCheckpointPin {
    height: 20912,
    block_id: [
        0xed, 0x71, 0xb4, 0xda, 0xd4, 0x6f, 0x43, 0xa3, 0x13, 0xa4, 0x82, 0x2b, 0xf0, 0xdc, 0x62, 0xfe,
        0xf4, 0xf2, 0x99, 0x97, 0xd3, 0x9c, 0x12, 0xcf, 0x96, 0xb7, 0x10, 0x7e, 0xea, 0x95, 0xa9, 0x67,
    ],
    ids: include_bytes!("data/mainnet-work-checkpoint-v1.ids"),
    ids_blake3: [
        0xc8, 0xfd, 0xe3, 0x4e, 0x92, 0x47, 0x8a, 0x85, 0x23, 0xc1, 0xf1, 0x3b, 0x7d, 0x30, 0x65, 0x82,
        0xe8, 0x41, 0xdb, 0x31, 0x84, 0x84, 0x42, 0x62, 0x54, 0xfe, 0x3a, 0x54, 0x16, 0x16, 0x6c, 0x26,
    ],
})
