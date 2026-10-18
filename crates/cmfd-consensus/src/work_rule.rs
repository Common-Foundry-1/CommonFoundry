//! Release checkpoint for ProductionV4 work re-execution.
//!
//! From the block after a release checkpoint `C`, nodes independently
//! re-execute each block's ForgeMatrix work from its header and nonce. At or
//! below `C` a block must instead carry the pinned canonical identifier for its
//! height, and above `C` it must descend from the checkpoint block. This module
//! holds only the checkpoint data; the node applies it at admission.
//!
//! The canonical identifiers are public block ids. A release ships the full
//! list `L[1..=C]` as `32 * C` bytes, entry `i` being the id at height `i + 1`,
//! together with the list's BLAKE3 digest. Nothing here enters
//! `NetworkParams::fingerprint`, so the network identity is unchanged.

use std::borrow::Cow;
use std::sync::OnceLock;

use thiserror::Error;

use crate::mainnet_network::is_mainnet_network;
use crate::wire::{PRODUCTION_V4_RCNET1_NETWORK_ID, PRODUCTION_V4_TESTNET_NETWORK_ID};

const ID_BYTES: usize = 32;

/// A compiled release checkpoint: height `C`, the block id at `C`, the
/// canonical id list `L[1..=C]` and the plain BLAKE3 hash of that list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkCheckpointPin {
    pub height: u64,
    pub block_id: [u8; 32],
    pub ids: &'static [u8],
    pub ids_blake3: [u8; 32],
}

/// Mainnet's checkpoint. `None` until the release cut fills it.
pub const MAINNET_WORK_CHECKPOINT: Option<WorkCheckpointPin> =
    include!("../mainnet_work_checkpoint.inc.rs");

/// RCNet-1's checkpoint. `None` until it is filled before the RCNet-1 deploy.
pub const RCNET1_WORK_CHECKPOINT: Option<WorkCheckpointPin> =
    include!("../rcnet1_work_checkpoint.inc.rs");

/// SHA-256("CMFD/PRODUCTION-V4-TESTNET/V1/VIRTUAL-GENESIS/2026-08-27"), the
/// V4 testnet's virtual genesis. The testnet checkpoint is its genesis (C = 0).
const PRODUCTION_V4_TESTNET_GENESIS: [u8; 32] = [
    0x2b, 0xda, 0x6e, 0x00, 0xa7, 0xd1, 0x86, 0xe5, 0x8b, 0x39, 0x20, 0xa1, 0x2d, 0x55, 0x21, 0xd9,
    0x78, 0xe6, 0x37, 0x64, 0x1f, 0xff, 0x97, 0xc8, 0xef, 0x0e, 0x10, 0xf9, 0x45, 0x00, 0xbb, 0xa6,
];

static PRODUCTION_V4_TESTNET_RULE: ForgeMatrixV4WorkRule = ForgeMatrixV4WorkRule {
    checkpoint_height: 0,
    checkpoint_block_id: PRODUCTION_V4_TESTNET_GENESIS,
    canonical_ids: Cow::Borrowed(&[]),
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkRuleError {
    #[error("checkpoint block id must be nonzero")]
    ZeroCheckpointId,
    #[error("canonical id list must hold exactly 32 bytes per height up to the checkpoint")]
    ListLength,
    #[error("canonical id at height {0} is zero")]
    ZeroId(u64),
    #[error("canonical id at the checkpoint height differs from the checkpoint block id")]
    CheckpointIdMismatch,
    #[error("pinned height {0} is outside 1..=checkpoint height")]
    PinOutOfRange(u64),
    #[error("height {0} is pinned to two different ids")]
    ConflictingPin(u64),
    #[error("canonical id list does not match its pinned BLAKE3 digest")]
    DigestMismatch,
}

/// The work rule of one ProductionV4 network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeMatrixV4WorkRule {
    checkpoint_height: u64,
    checkpoint_block_id: [u8; 32],
    /// `32 * checkpoint_height` bytes; entry `i` is the id at height `i + 1`.
    /// An all-zero entry means the height is not pinned (sparse test rules
    /// only; a release list has no zero entries).
    canonical_ids: Cow<'static, [u8]>,
}

impl ForgeMatrixV4WorkRule {
    /// A rule with a complete canonical id list. Every entry must be nonzero
    /// and the entry at `checkpoint_height` must equal `checkpoint_block_id`.
    /// With `checkpoint_height == 0` the list is empty and the checkpoint
    /// block is the network's virtual genesis.
    pub fn new(
        checkpoint_height: u64,
        checkpoint_block_id: [u8; 32],
        canonical_ids: &'static [u8],
    ) -> Result<Self, WorkRuleError> {
        let rule = Self::checked(
            checkpoint_height,
            checkpoint_block_id,
            Cow::Borrowed(canonical_ids),
        )?;
        if let Some(height) = (1..=checkpoint_height).find(|height| rule.entry(*height) == [0; 32])
        {
            return Err(WorkRuleError::ZeroId(height));
        }
        Ok(rule)
    }

    /// A rule that pins only the given heights at or below the checkpoint;
    /// the checkpoint height itself is always pinned to `checkpoint_block_id`.
    /// Unpinned heights are not constrained by the list. For tests and local
    /// qualification only (feature `work-rule-test-support`); compiled
    /// networks always use a complete list.
    #[cfg(any(test, feature = "work-rule-test-support"))]
    pub fn with_pinned_heights(
        checkpoint_height: u64,
        checkpoint_block_id: [u8; 32],
        pins: impl IntoIterator<Item = (u64, [u8; 32])>,
    ) -> Result<Self, WorkRuleError> {
        if checkpoint_block_id == [0; 32] {
            return Err(WorkRuleError::ZeroCheckpointId);
        }
        let length = usize::try_from(checkpoint_height)
            .ok()
            .and_then(|height| height.checked_mul(ID_BYTES))
            .ok_or(WorkRuleError::ListLength)?;
        let mut ids = vec![0_u8; length];
        let mut place = |height: u64, id: [u8; 32]| {
            if height == 0 || height > checkpoint_height {
                return Err(WorkRuleError::PinOutOfRange(height));
            }
            if id == [0; 32] {
                return Err(WorkRuleError::ZeroId(height));
            }
            let start = (height as usize - 1) * ID_BYTES;
            let slot = &mut ids[start..start + ID_BYTES];
            if slot != [0; 32] && slot != id {
                return Err(WorkRuleError::ConflictingPin(height));
            }
            slot.copy_from_slice(&id);
            Ok(())
        };
        for (height, id) in pins {
            place(height, id)?;
        }
        if checkpoint_height > 0 {
            place(checkpoint_height, checkpoint_block_id)
                .map_err(|_| WorkRuleError::CheckpointIdMismatch)?;
        }
        Self::checked(checkpoint_height, checkpoint_block_id, Cow::Owned(ids))
    }

    fn checked(
        checkpoint_height: u64,
        checkpoint_block_id: [u8; 32],
        canonical_ids: Cow<'static, [u8]>,
    ) -> Result<Self, WorkRuleError> {
        if checkpoint_block_id == [0; 32] {
            return Err(WorkRuleError::ZeroCheckpointId);
        }
        let expected = usize::try_from(checkpoint_height)
            .ok()
            .and_then(|height| height.checked_mul(ID_BYTES));
        if expected != Some(canonical_ids.len()) {
            return Err(WorkRuleError::ListLength);
        }
        let rule = Self {
            checkpoint_height,
            checkpoint_block_id,
            canonical_ids,
        };
        if checkpoint_height > 0 && rule.entry(checkpoint_height) != checkpoint_block_id {
            return Err(WorkRuleError::CheckpointIdMismatch);
        }
        Ok(rule)
    }

    /// Checkpoint height `C`.
    pub const fn checkpoint_height(&self) -> u64 {
        self.checkpoint_height
    }

    /// Block id at `C` (the virtual genesis when `C == 0`).
    pub const fn checkpoint_block_id(&self) -> [u8; 32] {
        self.checkpoint_block_id
    }

    /// First height whose work is re-executed: `C + 1`.
    pub const fn activation_height(&self) -> u64 {
        self.checkpoint_height + 1
    }

    /// Whether a block at `height` must have its work re-executed.
    pub const fn requires_recomputation(&self, height: u64) -> bool {
        height > self.checkpoint_height
    }

    /// The pinned canonical id at `height`, for `1..=C`. `None` at height 0,
    /// above `C`, and at heights a sparse test rule leaves unpinned.
    pub fn canonical_id(&self, height: u64) -> Option<[u8; 32]> {
        if height == 0 || height > self.checkpoint_height {
            return None;
        }
        Some(self.entry(height)).filter(|id| *id != [0; 32])
    }

    /// Whether a block with `block_id` at `height <= C` contradicts the
    /// canonical list. Blocks above `C` never conflict with the list; their
    /// checkpoint ancestry is checked against the node's index instead.
    pub fn conflicts_with_canonical_list(&self, height: u64, block_id: [u8; 32]) -> bool {
        self.canonical_id(height)
            .is_some_and(|canonical| canonical != block_id)
    }

    fn entry(&self, height: u64) -> [u8; 32] {
        let start = (height as usize - 1) * ID_BYTES;
        self.canonical_ids[start..start + ID_BYTES]
            .try_into()
            .expect("entry is 32 bytes")
    }
}

impl WorkCheckpointPin {
    /// Validate the pinned digest and build the rule from a complete list.
    pub fn rule(&self) -> Result<ForgeMatrixV4WorkRule, WorkRuleError> {
        if *blake3::hash(self.ids).as_bytes() != self.ids_blake3 {
            return Err(WorkRuleError::DigestMismatch);
        }
        ForgeMatrixV4WorkRule::new(self.height, self.block_id, self.ids)
    }
}

/// The work rule compiled for `network_id`, if any: mainnet and RCNet-1 once
/// their checkpoints are pinned, and the V4 testnet from its genesis. Other
/// networks (Devnet's reference proof) have none. Panics if the compiled
/// checkpoint list does not match its digest; a node checks that first with
/// [`forgematrix_v4_work_rule_checked`].
pub fn forgematrix_v4_work_rule(network_id: [u8; 32]) -> Option<&'static ForgeMatrixV4WorkRule> {
    forgematrix_v4_work_rule_checked(network_id)
        .expect("compiled work checkpoint is consistent with its digest")
}

/// [`forgematrix_v4_work_rule`], or the error if the checkpoint compiled for
/// `network_id` does not match its digest or does not form a rule.
pub fn forgematrix_v4_work_rule_checked(
    network_id: [u8; 32],
) -> Result<Option<&'static ForgeMatrixV4WorkRule>, WorkRuleError> {
    static MAINNET: OnceLock<ForgeMatrixV4WorkRule> = OnceLock::new();
    static RCNET1: OnceLock<ForgeMatrixV4WorkRule> = OnceLock::new();
    if network_id == PRODUCTION_V4_TESTNET_NETWORK_ID {
        return Ok(Some(&PRODUCTION_V4_TESTNET_RULE));
    }
    let (cell, pin) = if network_id == PRODUCTION_V4_RCNET1_NETWORK_ID {
        (&RCNET1, RCNET1_WORK_CHECKPOINT)
    } else if is_mainnet_network(network_id) {
        (&MAINNET, MAINNET_WORK_CHECKPOINT)
    } else {
        return Ok(None);
    };
    let Some(pin) = pin else {
        return Ok(None);
    };
    if let Some(rule) = cell.get() {
        return Ok(Some(rule));
    }
    let rule = pin.rule()?;
    Ok(Some(cell.get_or_init(|| rule)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn list(ids: &[[u8; 32]]) -> &'static [u8] {
        Box::leak(ids.concat().into_boxed_slice())
    }

    #[test]
    fn complete_list_selects_ids_by_height() {
        let rule = ForgeMatrixV4WorkRule::new(3, id(3), list(&[id(1), id(2), id(3)])).unwrap();
        assert_eq!(rule.checkpoint_height(), 3);
        assert_eq!(rule.checkpoint_block_id(), id(3));
        assert_eq!(rule.activation_height(), 4);
        assert_eq!(rule.canonical_id(0), None);
        assert_eq!(rule.canonical_id(1), Some(id(1)));
        assert_eq!(rule.canonical_id(2), Some(id(2)));
        assert_eq!(rule.canonical_id(3), Some(id(3)));
        assert_eq!(rule.canonical_id(4), None);
        assert!(!rule.requires_recomputation(0));
        assert!(!rule.requires_recomputation(3));
        assert!(rule.requires_recomputation(4));
        assert!(!rule.conflicts_with_canonical_list(2, id(2)));
        assert!(rule.conflicts_with_canonical_list(2, id(9)));
        assert!(!rule.conflicts_with_canonical_list(4, id(9)));
    }

    #[test]
    fn complete_list_is_validated() {
        assert_eq!(
            ForgeMatrixV4WorkRule::new(2, id(2), list(&[id(1)])),
            Err(WorkRuleError::ListLength)
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::new(1, id(1), list(&[id(1), id(2)])),
            Err(WorkRuleError::ListLength)
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::new(2, id(9), list(&[id(1), id(2)])),
            Err(WorkRuleError::CheckpointIdMismatch)
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::new(3, id(3), list(&[id(1), id(0), id(3)])),
            Err(WorkRuleError::ZeroId(2))
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::new(0, id(0), &[]),
            Err(WorkRuleError::ZeroCheckpointId)
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::new(0, id(7), list(&[id(7)])),
            Err(WorkRuleError::ListLength)
        );
    }

    #[test]
    fn checkpoint_at_genesis_recomputes_every_block() {
        let rule = ForgeMatrixV4WorkRule::new(0, id(7), &[]).unwrap();
        assert_eq!(rule.activation_height(), 1);
        assert_eq!(rule.checkpoint_block_id(), id(7));
        assert!(rule.requires_recomputation(1));
        assert_eq!(rule.canonical_id(0), None);
        assert_eq!(rule.canonical_id(1), None);
        assert!(!rule.conflicts_with_canonical_list(1, id(9)));
        assert_eq!(
            ForgeMatrixV4WorkRule::with_pinned_heights(0, id(7), []).unwrap(),
            rule
        );
    }

    #[test]
    fn sparse_rule_constrains_only_pinned_heights() {
        let rule = ForgeMatrixV4WorkRule::with_pinned_heights(5, id(5), [(2, id(2))]).unwrap();
        assert_eq!(rule.activation_height(), 6);
        assert_eq!(rule.canonical_id(1), None);
        assert_eq!(rule.canonical_id(2), Some(id(2)));
        assert_eq!(rule.canonical_id(3), None);
        assert_eq!(rule.canonical_id(5), Some(id(5)));
        assert!(!rule.conflicts_with_canonical_list(1, id(9)));
        assert!(rule.conflicts_with_canonical_list(2, id(9)));
        assert!(!rule.conflicts_with_canonical_list(3, id(9)));
        assert!(rule.conflicts_with_canonical_list(5, id(9)));
        // A pin repeated with the same id is accepted.
        assert!(
            ForgeMatrixV4WorkRule::with_pinned_heights(5, id(5), [(2, id(2)), (2, id(2))]).is_ok()
        );
    }

    #[test]
    fn sparse_rule_is_validated() {
        let sparse =
            |pins: Vec<(u64, [u8; 32])>| ForgeMatrixV4WorkRule::with_pinned_heights(5, id(5), pins);
        assert_eq!(
            sparse(vec![(0, id(1))]),
            Err(WorkRuleError::PinOutOfRange(0))
        );
        assert_eq!(
            sparse(vec![(6, id(1))]),
            Err(WorkRuleError::PinOutOfRange(6))
        );
        assert_eq!(sparse(vec![(2, id(0))]), Err(WorkRuleError::ZeroId(2)));
        assert_eq!(
            sparse(vec![(2, id(1)), (2, id(2))]),
            Err(WorkRuleError::ConflictingPin(2))
        );
        assert_eq!(
            sparse(vec![(5, id(4))]),
            Err(WorkRuleError::CheckpointIdMismatch)
        );
        assert_eq!(
            ForgeMatrixV4WorkRule::with_pinned_heights(5, id(0), []),
            Err(WorkRuleError::ZeroCheckpointId)
        );
    }

    #[test]
    fn pin_digest_is_checked() {
        let ids = list(&[id(1), id(2)]);
        let pin = WorkCheckpointPin {
            height: 2,
            block_id: id(2),
            ids,
            ids_blake3: *blake3::hash(ids).as_bytes(),
        };
        assert_eq!(
            pin.rule().unwrap(),
            ForgeMatrixV4WorkRule::new(2, id(2), ids).unwrap()
        );
        let wrong = WorkCheckpointPin {
            ids_blake3: [0; 32],
            ..pin
        };
        assert_eq!(wrong.rule(), Err(WorkRuleError::DigestMismatch));
    }

    #[test]
    fn networks_select_their_rule() {
        let testnet = forgematrix_v4_work_rule(PRODUCTION_V4_TESTNET_NETWORK_ID).unwrap();
        assert_eq!(testnet.checkpoint_height(), 0);
        assert_eq!(testnet.activation_height(), 1);
        assert_eq!(testnet.checkpoint_block_id(), PRODUCTION_V4_TESTNET_GENESIS);
        assert_eq!(
            *testnet,
            ForgeMatrixV4WorkRule::new(0, PRODUCTION_V4_TESTNET_GENESIS, &[]).unwrap()
        );

        for (network_id, pin) in [
            (PRODUCTION_V4_RCNET1_NETWORK_ID, RCNET1_WORK_CHECKPOINT),
            (
                crate::mainnet_network::MAINNET_NETWORK_ID.unwrap_or([0x5a; 32]),
                MAINNET_WORK_CHECKPOINT,
            ),
        ] {
            let selected = forgematrix_v4_work_rule(network_id);
            assert_eq!(forgematrix_v4_work_rule_checked(network_id), Ok(selected));
            match pin {
                None => assert!(selected.is_none()),
                Some(pin) => assert_eq!(selected, Some(&pin.rule().unwrap())),
            }
        }

        let mut other = PRODUCTION_V4_TESTNET_NETWORK_ID;
        other[0] ^= 1;
        assert!(forgematrix_v4_work_rule(other).is_none());
        assert!(forgematrix_v4_work_rule([0x42; 32]).is_none());
    }

    #[test]
    fn compiled_checkpoints_are_complete_and_match_their_digests() {
        for pin in [MAINNET_WORK_CHECKPOINT, RCNET1_WORK_CHECKPOINT]
            .into_iter()
            .flatten()
        {
            assert!(pin.height > 0);
            assert_eq!(pin.ids.len() as u64, 32 * pin.height);
            assert_eq!(&pin.ids[pin.ids.len() - 32..], &pin.block_id);
            assert_eq!(*blake3::hash(pin.ids).as_bytes(), pin.ids_blake3);
            let rule = pin.rule().unwrap();
            assert_eq!(rule.activation_height(), pin.height + 1);
            assert_eq!(rule.canonical_id(pin.height), Some(pin.block_id));
        }
    }

    #[test]
    #[ignore = "fails until the mainnet and RCNet-1 checkpoints are pinned"]
    fn release_checkpoints_are_pinned() {
        assert!(MAINNET_WORK_CHECKPOINT.is_some());
        assert!(RCNET1_WORK_CHECKPOINT.is_some());
    }
}
