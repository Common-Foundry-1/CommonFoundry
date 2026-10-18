//! `work-checkpoint export`: write the canonical id list `L[1..=C]` of a
//! release work checkpoint from the local active chain.
//!
//! The file holds `32 * C` bytes, entry `i` being the active block id at
//! height `i + 1`, which is the layout `cmfd_consensus::work_rule` pins. Every
//! entry is checked to sit at its height and to name the previous entry as its
//! parent, the first entry's parent being the virtual genesis. A release
//! checkpoint must sit at least [`MIN_CHECKPOINT_DEPTH`] blocks below the tip.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::Node;

/// Minimum number of active blocks above a release checkpoint at export time.
pub const MIN_CHECKPOINT_DEPTH: u64 = 100;

#[derive(Debug, Error)]
pub enum WorkCheckpointError {
    #[error("checkpoint height must be at least 1")]
    ZeroHeight,
    #[error("checkpoint height {height} is above the active tip {tip}")]
    AboveTip { height: u64, tip: u64 },
    #[error(
        "checkpoint height {height} is only {depth} blocks below the tip {tip} (need {min})",
        min = MIN_CHECKPOINT_DEPTH
    )]
    Shallow { height: u64, tip: u64, depth: u64 },
    #[error("active chain is not linked at height {0}")]
    Linkage(u64),
    #[error("{operation} failed for {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What `work-checkpoint export` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCheckpointExport {
    pub checkpoint_height: u64,
    pub checkpoint_block_id: [u8; 32],
    /// Plain BLAKE3 hash of the written file.
    pub ids_blake3: [u8; 32],
    pub bytes: u64,
    pub tip_height: u64,
    /// Active blocks above the checkpoint: `tip_height - checkpoint_height`.
    pub depth: u64,
}

impl Node {
    /// Active-chain ids at heights `1..=height`, concatenated, after checking
    /// each one's height and parent link.
    pub fn active_canonical_ids(&self, height: u64) -> Result<Vec<u8>, WorkCheckpointError> {
        if height == 0 {
            return Err(WorkCheckpointError::ZeroHeight);
        }
        let chain = &self.index.active_chain;
        let tip = chain.len().saturating_sub(1) as u64;
        if height > tip {
            return Err(WorkCheckpointError::AboveTip { height, tip });
        }
        if chain[0] != self.index.genesis {
            return Err(WorkCheckpointError::Linkage(0));
        }
        let entries = chain[1..=height as usize]
            .iter()
            .zip(1_u64..)
            .map(|(block_id, height)| {
                let located = self
                    .index
                    .blocks
                    .get(block_id)
                    .map(|entry| (entry.height(), entry.parent()));
                (height, *block_id, located)
            });
        linked_ids(self.index.genesis, entries)
    }

    /// Write `L[1..=height]` to a new file at `out` and report its identity.
    /// Unless `allow_shallow` is set (development networks and tests), the
    /// checkpoint must be at least [`MIN_CHECKPOINT_DEPTH`] blocks deep.
    pub fn export_work_checkpoint(
        &self,
        height: u64,
        out: &Path,
        allow_shallow: bool,
    ) -> Result<WorkCheckpointExport, WorkCheckpointError> {
        let ids = self.active_canonical_ids(height)?;
        let tip = self.index.active_chain.len() as u64 - 1;
        let depth = tip - height;
        if depth < MIN_CHECKPOINT_DEPTH && !allow_shallow {
            return Err(WorkCheckpointError::Shallow { height, tip, depth });
        }
        let io_error = |operation, source| WorkCheckpointError::Io {
            operation,
            path: out.to_path_buf(),
            source,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out)
            .map_err(|source| io_error("create work checkpoint file", source))?;
        if let Err(source) = file.write_all(&ids).and_then(|()| file.sync_all()) {
            // The file was created above, so a partial one is ours to remove.
            drop(file);
            let _ = std::fs::remove_file(out);
            return Err(io_error("write work checkpoint file", source));
        }
        Ok(WorkCheckpointExport {
            checkpoint_height: height,
            checkpoint_block_id: ids[ids.len() - 32..].try_into().expect("32-byte id"),
            ids_blake3: *blake3::hash(&ids).as_bytes(),
            bytes: ids.len() as u64,
            tip_height: tip,
            depth,
        })
    }
}

/// One active-chain entry: expected height, block id, and the indexed
/// `(height, parent)` when the block is in the index.
type ChainEntry = (u64, [u8; 32], Option<(u64, [u8; 32])>);

/// Concatenate entries that run from height 1 upward, each linked to the
/// one before it.
fn linked_ids(
    genesis: [u8; 32],
    entries: impl IntoIterator<Item = ChainEntry>,
) -> Result<Vec<u8>, WorkCheckpointError> {
    let mut ids = Vec::new();
    let mut previous = genesis;
    for (expected_height, block_id, located) in entries.into_iter() {
        let linked = located == Some((expected_height, previous)) && block_id != [0; 32];
        if !linked || ids.len() as u64 / 32 + 1 != expected_height {
            return Err(WorkCheckpointError::Linkage(expected_height));
        }
        ids.extend_from_slice(&block_id);
        previous = block_id;
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use cmfd_consensus::ForgeMatrixV4WorkRule;

    use super::*;
    use crate::{DEFAULT_MINING_ATTEMPTS, DEVNET_PROFILE};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cmfd-work-checkpoint-{label}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn devnet_node_with_blocks(directory: &TestDirectory, blocks: u64) -> Node {
        let mut node = Node::open_with_profile(directory.0.join("node"), DEVNET_PROFILE).unwrap();
        let miner = node.wallet_destination();
        for _ in 0..blocks {
            let timestamp =
                DEVNET_PROFILE.virtual_genesis_timestamp + node.state.next_height() * 60;
            node.mine_once(miner, timestamp, DEFAULT_MINING_ATTEMPTS)
                .unwrap();
        }
        node
    }

    #[test]
    fn export_writes_the_linked_active_chain() {
        let directory = TestDirectory::new("export");
        let node = devnet_node_with_blocks(&directory, 6);
        let out = directory.0.join("devnet.ids");
        // Four blocks deep is too shallow for a release checkpoint.
        assert!(matches!(
            node.export_work_checkpoint(4, &out, false),
            Err(WorkCheckpointError::Shallow {
                height: 4,
                tip: 6,
                depth: 2
            })
        ));
        assert!(!out.exists());
        let report = node.export_work_checkpoint(4, &out, true).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), 4 * 32);
        let expected: Vec<u8> = (1..=4)
            .flat_map(|height| node.active_block_id_at_height(height).unwrap())
            .collect();
        assert_eq!(bytes, expected);
        assert_eq!(
            report,
            WorkCheckpointExport {
                checkpoint_height: 4,
                checkpoint_block_id: node.active_block_id_at_height(4).unwrap(),
                ids_blake3: *blake3::hash(&bytes).as_bytes(),
                bytes: 128,
                tip_height: 6,
                depth: 2,
            }
        );

        // The file is exactly what a compiled checkpoint pins.
        let rule = ForgeMatrixV4WorkRule::new(
            4,
            report.checkpoint_block_id,
            Box::leak(bytes.into_boxed_slice()),
        )
        .unwrap();
        assert_eq!(rule.activation_height(), 5);
        for height in 1..=4 {
            assert_eq!(
                rule.canonical_id(height),
                node.active_block_id_at_height(height)
            );
        }

        // The whole chain can be exported; an existing file is never replaced.
        let tip = node
            .export_work_checkpoint(6, &directory.0.join("tip.ids"), true)
            .unwrap();
        assert_eq!((tip.bytes, tip.depth), (6 * 32, 0));
        assert!(matches!(
            node.export_work_checkpoint(2, &out, true),
            Err(WorkCheckpointError::Io { .. })
        ));
        assert_eq!(std::fs::read(&out).unwrap().len(), 4 * 32);
    }

    #[test]
    fn export_refuses_heights_outside_the_active_chain() {
        let directory = TestDirectory::new("bounds");
        let node = devnet_node_with_blocks(&directory, 2);
        assert!(matches!(
            node.export_work_checkpoint(0, &directory.0.join("zero.ids"), true),
            Err(WorkCheckpointError::ZeroHeight)
        ));
        assert!(matches!(
            node.export_work_checkpoint(3, &directory.0.join("above.ids"), true),
            Err(WorkCheckpointError::AboveTip { height: 3, tip: 2 })
        ));
        assert!(!directory.0.join("zero.ids").exists());
        assert!(!directory.0.join("above.ids").exists());
    }

    #[test]
    fn compiled_rules_match_the_network_profiles() {
        use cmfd_consensus::forgematrix_v4_work_rule;
        let testnet =
            forgematrix_v4_work_rule(crate::PRODUCTION_V4_TESTNET_PROFILE.network_id).unwrap();
        assert_eq!(testnet.checkpoint_height(), 0);
        assert_eq!(
            testnet.checkpoint_block_id(),
            crate::PRODUCTION_V4_TESTNET_PROFILE.virtual_genesis_hash
        );
        assert!(forgematrix_v4_work_rule(DEVNET_PROFILE.network_id).is_none());
        if let Some(rcnet) = forgematrix_v4_work_rule(crate::RCNET1_PROFILE.network_id) {
            assert!(rcnet.checkpoint_height() > 0);
        }
    }

    #[test]
    fn linkage_breaks_are_refused() {
        let genesis = [0xa0; 32];
        let (a, b, c) = ([0xa1; 32], [0xa2; 32], [0xa3; 32]);
        let good = vec![
            (1, a, Some((1, genesis))),
            (2, b, Some((2, a))),
            (3, c, Some((3, b))),
        ];
        assert_eq!(
            linked_ids(genesis, good.clone()).unwrap(),
            [a, b, c].concat()
        );

        let broken = |index: usize, entry: ChainEntry| {
            let mut entries = good.clone();
            entries[index] = entry;
            linked_ids(genesis, entries)
        };
        // Wrong parent, wrong indexed height, missing index entry, zero id.
        for (index, entry, height) in [
            (1, (2, b, Some((2, c))), 2),
            (2, (3, c, Some((4, b))), 3),
            (1, (2, b, None), 2),
            (0, (1, [0; 32], Some((1, genesis))), 1),
            (0, (1, a, Some((1, [0xff; 32]))), 1),
        ] {
            assert!(matches!(
                broken(index, entry),
                Err(WorkCheckpointError::Linkage(h)) if h == height
            ));
        }
        // Entries must start at height 1 and be contiguous.
        assert!(matches!(
            linked_ids(genesis, vec![(2, a, Some((2, genesis)))]),
            Err(WorkCheckpointError::Linkage(2))
        ));
    }
}
