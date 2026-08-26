use std::{cmp::Ordering, collections::HashMap, mem::size_of};

use blake3::Hasher;
use thiserror::Error;

use super::{
    ChainState, MembershipChange, OutPoint, OutputChange, OutputLock, TxOutput, UtxoDelta,
    ValidatedBlock, median_timestamp,
};
use crate::{
    DifficultyError, HeaderWork, MAX_BLOCK_AGGREGATE_INPUTS, MAX_BLOCK_AGGREGATE_OUTPUTS,
    MAX_BLOCK_TRANSACTIONS, MAX_COINBASE_OUTPUTS, MEDIAN_TIME_WINDOW, NetworkError, NetworkParams,
    next_work_target,
};

const REVERSIBLE_STATE_DELTA_MAGIC: [u8; 8] = *b"CMFDRSD\0";
const REVERSIBLE_STATE_DELTA_VERSION: u32 = 1;
const REVERSIBLE_STATE_DELTA_LOCAL_INTEGRITY_DOMAIN: &str =
    "CMFD/REVERSIBLE-STATE-DELTA/LOCAL-INTEGRITY/V1";

const OUTPOINT_BYTES: usize = 32 + 4;
const TX_OUTPUT_BYTES: usize = 8 + 1 + 32 + 8;
const OUTPUT_CHANGE_FIXED_BYTES: usize = OUTPOINT_BYTES + 1 + 1;
const MEMBERSHIP_CHANGE_BYTES: usize = 32 + 1 + 1;
const DELTA_COUNT_BYTES: usize = 4;
const DELTA_LOCAL_INTEGRITY_BYTES: usize = 32;

const MAX_OUTPUT_VALUE_OCCURRENCES: usize =
    MAX_BLOCK_AGGREGATE_INPUTS + MAX_BLOCK_AGGREGATE_OUTPUTS + MAX_COINBASE_OUTPUTS;
const MAX_OUTPUT_CHANGES: usize = MAX_OUTPUT_VALUE_OCCURRENCES;
const MAX_ACTIVE_CHANNEL_CHANGES: usize = MAX_BLOCK_AGGREGATE_OUTPUTS;
const MAX_RETIRED_CHANNEL_CHANGES: usize = MAX_BLOCK_TRANSACTIONS;

const REVERSIBLE_STATE_DELTA_FIXED_BYTES: usize = REVERSIBLE_STATE_DELTA_MAGIC.len()
    + size_of::<u32>()
    + 5 * 32
    + size_of::<[u64; 8]>()
    + 3 * DELTA_COUNT_BYTES
    + DELTA_LOCAL_INTEGRITY_BYTES;

/// Exact upper bound for the canonical codec under the current consensus
/// resource limits. Output replacements count both their previous and next
/// values against `MAX_OUTPUT_VALUE_OCCURRENCES`.
const MAX_RESOURCE_SHAPED_REVERSIBLE_STATE_DELTA_BYTES: usize = REVERSIBLE_STATE_DELTA_FIXED_BYTES
    + MAX_OUTPUT_CHANGES * OUTPUT_CHANGE_FIXED_BYTES
    + MAX_OUTPUT_VALUE_OCCURRENCES * TX_OUTPUT_BYTES
    + MAX_ACTIVE_CHANNEL_CHANGES * MEMBERSHIP_CHANGE_BYTES
    + MAX_RETIRED_CHANNEL_CHANGES * MEMBERSHIP_CHANGE_BYTES;

/// Maximum complete canonical reversible-state-delta frame, including its
/// local integrity digest.
pub const MAX_REVERSIBLE_STATE_DELTA_BYTES: usize = 1024 * 1024;

const _: () =
    assert!(MAX_RESOURCE_SHAPED_REVERSIBLE_STATE_DELTA_BYTES <= MAX_REVERSIBLE_STATE_DELTA_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReversibleStateDelta {
    network_fingerprint: [u8; 32],
    base_tip: [u8; 32],
    child_tip: [u8; 32],
    base_next_height: u64,
    child_next_height: u64,
    base_expected_target: [u8; 32],
    base_median_time_past: u64,
    base_history_len: u64,
    base_timestamp_len: u64,
    fees: u64,
    timestamp: u64,
    effective_timestamp: u64,
    target: [u8; 32],
    delta: UtxoDelta,
}

/// A canonical persisted delta that has passed structural decoding and local
/// corruption checks, but has not been authenticated by block validation.
///
/// This type deliberately cannot mutate chain state. The embedded BLAKE3
/// digest is only a local corruption and record-mix-up binding: it is not
/// trustless state authentication because Common Foundry does not currently
/// commit a state root in consensus. Call [`Self::promote_exact`] with the
/// result of full validation for the same block before using the delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedReversibleStateDelta {
    delta: ReversibleStateDelta,
    canonical_bytes: Box<[u8]>,
}

/// A reversible delta issued only by full block validation, or by exact-byte
/// promotion against that same validation result.
///
/// Its fields and constructor are private so decoded disk bytes cannot be
/// confused with consensus-authenticated state transition evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedReversibleStateDelta(ReversibleStateDelta);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReversibleStateDeltaError {
    #[error("network parameters are invalid: {0}")]
    Network(#[from] NetworkError),
    #[error("difficulty history is invalid: {0}")]
    Difficulty(#[from] DifficultyError),
    #[error("reversible state delta length {actual} exceeds the {maximum}-byte limit")]
    TooLarge { actual: usize, maximum: usize },
    #[error("reversible state delta ended before all canonical fields were decoded")]
    Truncated,
    #[error("reversible state delta has an invalid magic value")]
    InvalidMagic,
    #[error("unsupported reversible state delta version {0}")]
    UnsupportedVersion(u32),
    #[error("reversible state delta failed its local integrity binding")]
    LocalIntegrityMismatch,
    #[error("reversible state delta {0} binding does not match the expected block path")]
    BindingMismatch(&'static str),
    #[error("reversible state delta {section} count {actual} exceeds limit {maximum}")]
    CountLimit {
        section: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("reversible state delta contains an invalid {field} tag {tag}")]
    InvalidTag { field: &'static str, tag: u8 },
    #[error("reversible state delta {0} entries are not in strict canonical order")]
    NonCanonicalOrder(&'static str),
    #[error("reversible state delta contains a no-op {0} change")]
    NoOpChange(&'static str),
    #[error("reversible state delta has an invalid {0}")]
    InvalidStructure(&'static str),
    #[error("reversible state delta has trailing bytes")]
    TrailingBytes,
    #[error("reversible state delta size calculation overflowed")]
    SizeOverflow,
    #[error("reversible state delta does not match the current child state")]
    StateMismatch,
    #[error("decoded reversible state delta does not exactly match the fully validated block")]
    ValidationMismatch,
}

impl ValidatedBlock {
    /// Encodes the state transition produced by full block validation.
    pub fn encode_reversible_state_delta(&self) -> Result<Vec<u8>, ReversibleStateDeltaError> {
        ReversibleStateDelta::from_validated(self)?.encode()
    }

    /// Issues an in-memory reversible delta directly from full block
    /// validation. No decoded or caller-constructed value can enter this type.
    pub fn validated_reversible_state_delta(
        &self,
    ) -> Result<ValidatedReversibleStateDelta, ReversibleStateDeltaError> {
        Ok(ValidatedReversibleStateDelta(
            ReversibleStateDelta::from_validated(self)?,
        ))
    }
}

impl ReversibleStateDelta {
    fn from_validated(validated: &ValidatedBlock) -> Result<Self, ReversibleStateDeltaError> {
        let delta = Self {
            network_fingerprint: validated.params.fingerprint()?,
            base_tip: validated.base_tip,
            child_tip: validated.next_tip,
            base_next_height: validated.base_next_height,
            child_next_height: validated.next_height,
            base_expected_target: validated.base_expected_target,
            base_median_time_past: validated.base_median_time_past,
            base_history_len: u64::try_from(validated.base_history_len)
                .map_err(|_| ReversibleStateDeltaError::SizeOverflow)?,
            base_timestamp_len: u64::try_from(validated.base_timestamp_len)
                .map_err(|_| ReversibleStateDeltaError::SizeOverflow)?,
            fees: validated.fees,
            timestamp: validated.timestamp,
            effective_timestamp: validated.effective_timestamp,
            target: validated.target,
            delta: validated.delta.clone(),
        };
        delta.validate_structure()?;
        Ok(delta)
    }
}

impl DecodedReversibleStateDelta {
    /// Decodes a complete canonical frame and binds it to the expected network
    /// and block edge. The returned value is intentionally unable to mutate
    /// chain state until [`Self::promote_exact`] authenticates it against full
    /// block validation.
    pub fn decode_bound(
        bytes: &[u8],
        params: &NetworkParams,
        expected_base_tip: [u8; 32],
        expected_child_tip: [u8; 32],
    ) -> Result<Self, ReversibleStateDeltaError> {
        if bytes.len() > MAX_REVERSIBLE_STATE_DELTA_BYTES {
            return Err(ReversibleStateDeltaError::TooLarge {
                actual: bytes.len(),
                maximum: MAX_REVERSIBLE_STATE_DELTA_BYTES,
            });
        }
        if bytes.len() < REVERSIBLE_STATE_DELTA_FIXED_BYTES {
            return Err(ReversibleStateDeltaError::Truncated);
        }

        let payload_len = bytes
            .len()
            .checked_sub(DELTA_LOCAL_INTEGRITY_BYTES)
            .ok_or(ReversibleStateDeltaError::Truncated)?;
        let (payload, encoded_digest) = bytes.split_at(payload_len);
        if local_integrity_digest(payload).as_slice() != encoded_digest {
            return Err(ReversibleStateDeltaError::LocalIntegrityMismatch);
        }

        let mut reader = DeltaReader::new(payload);
        if reader.array::<8>()? != REVERSIBLE_STATE_DELTA_MAGIC {
            return Err(ReversibleStateDeltaError::InvalidMagic);
        }
        let version = reader.u32()?;
        if version != REVERSIBLE_STATE_DELTA_VERSION {
            return Err(ReversibleStateDeltaError::UnsupportedVersion(version));
        }

        let network_fingerprint = reader.array()?;
        if network_fingerprint != params.fingerprint()? {
            return Err(ReversibleStateDeltaError::BindingMismatch(
                "network fingerprint",
            ));
        }
        let base_tip = reader.array()?;
        if base_tip != expected_base_tip {
            return Err(ReversibleStateDeltaError::BindingMismatch("base tip"));
        }
        let child_tip = reader.array()?;
        if child_tip != expected_child_tip {
            return Err(ReversibleStateDeltaError::BindingMismatch("child tip"));
        }

        let base_next_height = reader.u64()?;
        let child_next_height = reader.u64()?;
        let base_expected_target = reader.array()?;
        let base_median_time_past = reader.u64()?;
        let base_history_len = reader.u64()?;
        let base_timestamp_len = reader.u64()?;
        let fees = reader.u64()?;
        let timestamp = reader.u64()?;
        let effective_timestamp = reader.u64()?;
        let target = reader.array()?;

        let outputs = decode_output_changes(&mut reader)?;
        let active_channels =
            decode_membership_changes(&mut reader, "active channel", MAX_ACTIVE_CHANNEL_CHANGES)?;
        let retired_channels =
            decode_membership_changes(&mut reader, "retired channel", MAX_RETIRED_CHANNEL_CHANGES)?;
        if !reader.is_finished() {
            return Err(ReversibleStateDeltaError::TrailingBytes);
        }

        let delta = ReversibleStateDelta {
            network_fingerprint,
            base_tip,
            child_tip,
            base_next_height,
            child_next_height,
            base_expected_target,
            base_median_time_past,
            base_history_len,
            base_timestamp_len,
            fees,
            timestamp,
            effective_timestamp,
            target,
            delta: UtxoDelta {
                outputs,
                active_channels,
                retired_channels,
            },
        };
        delta.validate_structure()?;
        if delta.encode()?.as_slice() != bytes {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "non-canonical encoding",
            ));
        }
        Ok(Self {
            delta,
            canonical_bytes: bytes.into(),
        })
    }

    /// Promotes decoded disk bytes only when they are byte-for-byte identical
    /// to the canonical transition freshly rederived by full validation of the
    /// same block. There is intentionally no digest-only or boolean shortcut.
    pub fn promote_exact(
        self,
        validated: &ValidatedBlock,
    ) -> Result<ValidatedReversibleStateDelta, ReversibleStateDeltaError> {
        let expected = ReversibleStateDelta::from_validated(validated)?;
        let expected_bytes = expected.encode()?;
        if self.delta != expected || self.canonical_bytes.as_ref() != expected_bytes.as_slice() {
            return Err(ReversibleStateDeltaError::ValidationMismatch);
        }
        Ok(ValidatedReversibleStateDelta(expected))
    }
}

impl ReversibleStateDelta {
    fn encode(&self) -> Result<Vec<u8>, ReversibleStateDeltaError> {
        self.validate_structure()?;
        let encoded_len = self.encoded_len()?;
        if encoded_len > MAX_REVERSIBLE_STATE_DELTA_BYTES {
            return Err(ReversibleStateDeltaError::TooLarge {
                actual: encoded_len,
                maximum: MAX_REVERSIBLE_STATE_DELTA_BYTES,
            });
        }

        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&REVERSIBLE_STATE_DELTA_MAGIC);
        push_u32(&mut bytes, REVERSIBLE_STATE_DELTA_VERSION);
        bytes.extend_from_slice(&self.network_fingerprint);
        bytes.extend_from_slice(&self.base_tip);
        bytes.extend_from_slice(&self.child_tip);
        push_u64(&mut bytes, self.base_next_height);
        push_u64(&mut bytes, self.child_next_height);
        bytes.extend_from_slice(&self.base_expected_target);
        push_u64(&mut bytes, self.base_median_time_past);
        push_u64(&mut bytes, self.base_history_len);
        push_u64(&mut bytes, self.base_timestamp_len);
        push_u64(&mut bytes, self.fees);
        push_u64(&mut bytes, self.timestamp);
        push_u64(&mut bytes, self.effective_timestamp);
        bytes.extend_from_slice(&self.target);

        let mut output_changes = self.delta.outputs.iter().collect::<Vec<_>>();
        output_changes.sort_unstable_by(|(left, _), (right, _)| compare_outpoints(left, right));
        push_u32(
            &mut bytes,
            u32::try_from(output_changes.len())
                .map_err(|_| ReversibleStateDeltaError::SizeOverflow)?,
        );
        for (outpoint, change) in output_changes {
            encode_outpoint(*outpoint, &mut bytes);
            encode_optional_output(change.previous.as_ref(), &mut bytes);
            encode_optional_output(change.next.as_ref(), &mut bytes);
        }

        encode_membership_changes(&self.delta.active_channels, &mut bytes)?;
        encode_membership_changes(&self.delta.retired_channels, &mut bytes)?;

        let digest = local_integrity_digest(&bytes);
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    fn encoded_len(&self) -> Result<usize, ReversibleStateDeltaError> {
        let output_occurrences = self.output_value_occurrences()?;
        REVERSIBLE_STATE_DELTA_FIXED_BYTES
            .checked_add(
                self.delta
                    .outputs
                    .len()
                    .checked_mul(OUTPUT_CHANGE_FIXED_BYTES)
                    .ok_or(ReversibleStateDeltaError::SizeOverflow)?,
            )
            .and_then(|length| {
                output_occurrences
                    .checked_mul(TX_OUTPUT_BYTES)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .and_then(|length| {
                self.delta
                    .active_channels
                    .len()
                    .checked_mul(MEMBERSHIP_CHANGE_BYTES)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .and_then(|length| {
                self.delta
                    .retired_channels
                    .len()
                    .checked_mul(MEMBERSHIP_CHANGE_BYTES)
                    .and_then(|bytes| length.checked_add(bytes))
            })
            .ok_or(ReversibleStateDeltaError::SizeOverflow)
    }

    fn output_value_occurrences(&self) -> Result<usize, ReversibleStateDeltaError> {
        self.delta
            .outputs
            .values()
            .try_fold(0usize, |count, change| {
                count
                    .checked_add(usize::from(change.previous.is_some()))
                    .and_then(|count| count.checked_add(usize::from(change.next.is_some())))
                    .ok_or(ReversibleStateDeltaError::SizeOverflow)
            })
    }

    fn validate_structure(&self) -> Result<(), ReversibleStateDeltaError> {
        if self.base_next_height == 0 {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "zero base height",
            ));
        }
        if self.child_next_height
            != self.base_next_height.checked_add(1).ok_or(
                ReversibleStateDeltaError::InvalidStructure("height transition"),
            )?
        {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "height transition",
            ));
        }
        if self.base_history_len != self.base_next_height
            || self.base_timestamp_len != self.base_next_height
        {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "base history lengths",
            ));
        }
        if self.base_expected_target == [0; 32] || self.target == [0; 32] {
            return Err(ReversibleStateDeltaError::InvalidStructure("zero target"));
        }
        if self.target != self.base_expected_target {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "target transition",
            ));
        }
        if self.timestamp <= self.base_median_time_past {
            return Err(ReversibleStateDeltaError::InvalidStructure(
                "timestamp not above median time past",
            ));
        }
        check_count(
            "output change",
            self.delta.outputs.len(),
            MAX_OUTPUT_CHANGES,
        )?;
        check_count(
            "active channel",
            self.delta.active_channels.len(),
            MAX_ACTIVE_CHANNEL_CHANGES,
        )?;
        check_count(
            "retired channel",
            self.delta.retired_channels.len(),
            MAX_RETIRED_CHANNEL_CHANGES,
        )?;
        check_count(
            "output value",
            self.output_value_occurrences()?,
            MAX_OUTPUT_VALUE_OCCURRENCES,
        )?;
        for change in self.delta.outputs.values() {
            if change.previous == change.next {
                return Err(ReversibleStateDeltaError::NoOpChange("output"));
            }
            for output in [change.previous.as_ref(), change.next.as_ref()]
                .into_iter()
                .flatten()
            {
                if output.value == 0 {
                    return Err(ReversibleStateDeltaError::InvalidStructure(
                        "zero-value output",
                    ));
                }
            }
        }
        for change in self
            .delta
            .active_channels
            .values()
            .chain(self.delta.retired_channels.values())
        {
            if change.previous == change.next {
                return Err(ReversibleStateDeltaError::NoOpChange("channel membership"));
            }
        }
        for channel_id in self.delta.active_channels.keys() {
            if let Some(retired) = self.delta.retired_channels.get(channel_id) {
                let active = &self.delta.active_channels[channel_id];
                if (active.previous && retired.previous) || (active.next && retired.next) {
                    return Err(ReversibleStateDeltaError::InvalidStructure(
                        "simultaneously active and retired channel",
                    ));
                }
            }
        }
        if self.encoded_len()? > MAX_REVERSIBLE_STATE_DELTA_BYTES {
            return Err(ReversibleStateDeltaError::TooLarge {
                actual: self.encoded_len()?,
                maximum: MAX_REVERSIBLE_STATE_DELTA_BYTES,
            });
        }
        Ok(())
    }
}

impl ChainState {
    /// Atomically undoes one canonical child transition. Every scalar and
    /// touched value is checked before any state mutation occurs.
    pub fn undo_reversible_state_delta(
        &mut self,
        delta: ValidatedReversibleStateDelta,
    ) -> Result<(), ReversibleStateDeltaError> {
        let delta = delta.0;
        delta.validate_structure()?;
        let base_history_len = usize::try_from(delta.base_history_len)
            .map_err(|_| ReversibleStateDeltaError::StateMismatch)?;
        let base_timestamp_len = usize::try_from(delta.base_timestamp_len)
            .map_err(|_| ReversibleStateDeltaError::StateMismatch)?;
        let expected_history_len = base_history_len
            .checked_add(1)
            .ok_or(ReversibleStateDeltaError::StateMismatch)?;
        let expected_timestamp_len = base_timestamp_len
            .checked_add(1)
            .ok_or(ReversibleStateDeltaError::StateMismatch)?;

        if self.params.fingerprint()? != delta.network_fingerprint
            || self.tip != delta.child_tip
            || self.next_height != delta.child_next_height
            || self.history.len() != expected_history_len
            || self.raw_timestamps.len() != expected_timestamp_len
            || self.history.last()
                != Some(&HeaderWork {
                    timestamp: delta.effective_timestamp,
                    target: delta.target,
                })
            || self.raw_timestamps.last() != Some(&delta.timestamp)
            || median_timestamp(&self.raw_timestamps[..base_timestamp_len])
                != delta.base_median_time_past
            || effective_timestamp_for_child(
                &self.raw_timestamps[..base_timestamp_len],
                delta.timestamp,
            ) != delta.effective_timestamp
            || next_work_target(&self.history[..base_history_len], self.params.pow_limit)?
                != delta.base_expected_target
            || !delta_matches_next(&delta.delta, self)
            || !delta_channel_memberships_are_disjoint(&delta.delta, self)
        {
            return Err(ReversibleStateDeltaError::StateMismatch);
        }

        apply_previous(delta.delta, self);
        self.history.pop();
        self.raw_timestamps.pop();
        self.tip = delta.base_tip;
        self.next_height = delta.base_next_height;
        Ok(())
    }

    /// Checked heuristic for the logical heap payload uniquely owned by this
    /// chain state.
    ///
    /// This is not a portable allocator or process-RSS upper bound: Rust does
    /// not promise a `HashMap` bucket layout, and shared verifier allocations,
    /// allocator metadata, fragmentation, stacks, mappings, and other process
    /// memory are excluded. Node policy must enforce an independent hard RSS
    /// or job/cgroup limit; this estimate is only an earlier budget signal.
    pub fn estimated_unique_heap_payload_bytes(&self) -> Result<usize, ReversibleStateDeltaError> {
        let mut bytes = size_of::<Self>();
        bytes = checked_add(
            bytes,
            hash_table_heap_payload_estimate::<OutPoint, TxOutput>(self.utxos.outputs.capacity())?,
        )?;
        bytes = checked_add(
            bytes,
            hash_table_heap_payload_estimate::<[u8; 32], ()>(
                self.utxos.active_channels.capacity(),
            )?,
        )?;
        bytes = checked_add(
            bytes,
            hash_table_heap_payload_estimate::<[u8; 32], ()>(
                self.utxos.retired_channels.capacity(),
            )?,
        )?;
        bytes = checked_add(
            bytes,
            vec_heap_payload_estimate::<HeaderWork>(self.history.capacity())?,
        )?;
        checked_add(
            bytes,
            vec_heap_payload_estimate::<u64>(self.raw_timestamps.capacity())?,
        )
    }
}

fn effective_timestamp_for_child(base_timestamps: &[u64], child_timestamp: u64) -> u64 {
    let window_start = base_timestamps
        .len()
        .saturating_sub(MEDIAN_TIME_WINDOW.saturating_sub(1));
    let mut window = Vec::with_capacity(base_timestamps.len() - window_start + 1);
    window.extend_from_slice(&base_timestamps[window_start..]);
    window.push(child_timestamp);
    median_timestamp(&window)
}

fn delta_matches_next(delta: &UtxoDelta, state: &ChainState) -> bool {
    delta
        .outputs
        .iter()
        .all(|(outpoint, change)| state.utxos.outputs.get(outpoint) == change.next.as_ref())
        && delta.active_channels.iter().all(|(channel_id, change)| {
            state.utxos.active_channels.contains(channel_id) == change.next
        })
        && delta.retired_channels.iter().all(|(channel_id, change)| {
            state.utxos.retired_channels.contains(channel_id) == change.next
        })
}

fn delta_channel_memberships_are_disjoint(delta: &UtxoDelta, state: &ChainState) -> bool {
    delta
        .active_channels
        .keys()
        .chain(delta.retired_channels.keys())
        .all(|channel_id| {
            let next_active = delta.active_channels.get(channel_id).map_or_else(
                || state.utxos.active_channels.contains(channel_id),
                |change| change.next,
            );
            let next_retired = delta.retired_channels.get(channel_id).map_or_else(
                || state.utxos.retired_channels.contains(channel_id),
                |change| change.next,
            );
            let previous_active = delta
                .active_channels
                .get(channel_id)
                .map_or(next_active, |change| change.previous);
            let previous_retired = delta
                .retired_channels
                .get(channel_id)
                .map_or(next_retired, |change| change.previous);
            !(next_active && next_retired || previous_active && previous_retired)
        })
}

fn apply_previous(delta: UtxoDelta, state: &mut ChainState) {
    for (outpoint, change) in delta.outputs {
        match change.previous {
            Some(output) => {
                state.utxos.outputs.insert(outpoint, output);
            }
            None => {
                state.utxos.outputs.remove(&outpoint);
            }
        }
    }
    for (channel_id, change) in delta.active_channels {
        if change.previous {
            state.utxos.active_channels.insert(channel_id);
        } else {
            state.utxos.active_channels.remove(&channel_id);
        }
    }
    for (channel_id, change) in delta.retired_channels {
        if change.previous {
            state.utxos.retired_channels.insert(channel_id);
        } else {
            state.utxos.retired_channels.remove(&channel_id);
        }
    }
}

fn encode_membership_changes(
    changes: &HashMap<[u8; 32], MembershipChange>,
    bytes: &mut Vec<u8>,
) -> Result<(), ReversibleStateDeltaError> {
    let mut entries = changes.iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(channel_id, _)| **channel_id);
    push_u32(
        bytes,
        u32::try_from(entries.len()).map_err(|_| ReversibleStateDeltaError::SizeOverflow)?,
    );
    for (channel_id, change) in entries {
        bytes.extend_from_slice(channel_id);
        bytes.push(u8::from(change.previous));
        bytes.push(u8::from(change.next));
    }
    Ok(())
}

fn decode_output_changes(
    reader: &mut DeltaReader<'_>,
) -> Result<HashMap<OutPoint, OutputChange>, ReversibleStateDeltaError> {
    let count =
        usize::try_from(reader.u32()?).map_err(|_| ReversibleStateDeltaError::SizeOverflow)?;
    check_count("output change", count, MAX_OUTPUT_CHANGES)?;
    reader.ensure_minimum_remaining(count, OUTPUT_CHANGE_FIXED_BYTES)?;
    let mut changes = HashMap::with_capacity(count);
    let mut previous_outpoint = None;
    for _ in 0..count {
        let outpoint = decode_outpoint(reader)?;
        if previous_outpoint
            .is_some_and(|previous| compare_outpoints(&previous, &outpoint) != Ordering::Less)
        {
            return Err(ReversibleStateDeltaError::NonCanonicalOrder(
                "output change",
            ));
        }
        previous_outpoint = Some(outpoint);
        let previous = decode_optional_output(reader)?;
        let next = decode_optional_output(reader)?;
        if previous == next {
            return Err(ReversibleStateDeltaError::NoOpChange("output"));
        }
        changes.insert(outpoint, OutputChange { previous, next });
    }
    Ok(changes)
}

fn decode_membership_changes(
    reader: &mut DeltaReader<'_>,
    section: &'static str,
    maximum: usize,
) -> Result<HashMap<[u8; 32], MembershipChange>, ReversibleStateDeltaError> {
    let count =
        usize::try_from(reader.u32()?).map_err(|_| ReversibleStateDeltaError::SizeOverflow)?;
    check_count(section, count, maximum)?;
    reader.ensure_minimum_remaining(count, MEMBERSHIP_CHANGE_BYTES)?;
    let mut changes = HashMap::with_capacity(count);
    let mut previous_channel = None;
    for _ in 0..count {
        let channel_id = reader.array()?;
        if previous_channel.is_some_and(|previous| previous >= channel_id) {
            return Err(ReversibleStateDeltaError::NonCanonicalOrder(section));
        }
        previous_channel = Some(channel_id);
        let previous = reader.bool("membership boolean")?;
        let next = reader.bool("membership boolean")?;
        if previous == next {
            return Err(ReversibleStateDeltaError::NoOpChange("channel membership"));
        }
        changes.insert(channel_id, MembershipChange { previous, next });
    }
    Ok(changes)
}

fn encode_outpoint(outpoint: OutPoint, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&outpoint.txid);
    push_u32(bytes, outpoint.index);
}

fn decode_outpoint(reader: &mut DeltaReader<'_>) -> Result<OutPoint, ReversibleStateDeltaError> {
    Ok(OutPoint {
        txid: reader.array()?,
        index: reader.u32()?,
    })
}

fn encode_optional_output(output: Option<&TxOutput>, bytes: &mut Vec<u8>) {
    match output {
        None => bytes.push(0),
        Some(output) => {
            bytes.push(1);
            push_u64(bytes, output.value);
            match output.lock {
                OutputLock::Key(owner) => {
                    bytes.push(0);
                    bytes.extend_from_slice(&owner);
                }
                OutputLock::InferenceChannel { channel_id } => {
                    bytes.push(1);
                    bytes.extend_from_slice(&channel_id);
                }
            }
            push_u64(bytes, output.spendable_height);
        }
    }
}

fn decode_optional_output(
    reader: &mut DeltaReader<'_>,
) -> Result<Option<TxOutput>, ReversibleStateDeltaError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let value = reader.u64()?;
            if value == 0 {
                return Err(ReversibleStateDeltaError::InvalidStructure(
                    "zero-value output",
                ));
            }
            let lock = match reader.u8()? {
                0 => OutputLock::Key(reader.array()?),
                1 => OutputLock::InferenceChannel {
                    channel_id: reader.array()?,
                },
                tag => {
                    return Err(ReversibleStateDeltaError::InvalidTag {
                        field: "output lock",
                        tag,
                    });
                }
            };
            Ok(Some(TxOutput {
                value,
                lock,
                spendable_height: reader.u64()?,
            }))
        }
        tag => Err(ReversibleStateDeltaError::InvalidTag {
            field: "optional output",
            tag,
        }),
    }
}

fn compare_outpoints(left: &OutPoint, right: &OutPoint) -> Ordering {
    left.txid
        .cmp(&right.txid)
        .then_with(|| left.index.cmp(&right.index))
}

fn check_count(
    section: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ReversibleStateDeltaError> {
    if actual > maximum {
        return Err(ReversibleStateDeltaError::CountLimit {
            section,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn local_integrity_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(REVERSIBLE_STATE_DELTA_LOCAL_INTEGRITY_DOMAIN);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

struct DeltaReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DeltaReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, ReversibleStateDeltaError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, ReversibleStateDeltaError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(ReversibleStateDeltaError::InvalidTag { field, tag }),
        }
    }

    fn u32(&mut self) -> Result<u32, ReversibleStateDeltaError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ReversibleStateDeltaError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReversibleStateDeltaError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ReversibleStateDeltaError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ReversibleStateDeltaError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ReversibleStateDeltaError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReversibleStateDeltaError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn ensure_minimum_remaining(
        &self,
        count: usize,
        bytes_per_entry: usize,
    ) -> Result<(), ReversibleStateDeltaError> {
        let required = count
            .checked_mul(bytes_per_entry)
            .ok_or(ReversibleStateDeltaError::SizeOverflow)?;
        if self.bytes.len().saturating_sub(self.offset) < required {
            return Err(ReversibleStateDeltaError::Truncated);
        }
        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

const HASH_TABLE_BUCKET_EXPANSION: usize = 4;
const ALLOCATION_OVERHEAD_BYTES: usize = 64;

fn hash_table_heap_payload_estimate<K, V>(
    capacity: usize,
) -> Result<usize, ReversibleStateDeltaError> {
    if capacity == 0 {
        return Ok(0);
    }
    let buckets = capacity
        .checked_add(1)
        .and_then(|capacity| capacity.checked_mul(HASH_TABLE_BUCKET_EXPANSION))
        .ok_or(ReversibleStateDeltaError::SizeOverflow)?;
    let bytes_per_bucket = size_of::<(K, V)>()
        .checked_add(1)
        .ok_or(ReversibleStateDeltaError::SizeOverflow)?;
    buckets
        .checked_mul(bytes_per_bucket)
        .and_then(|bytes| bytes.checked_add(ALLOCATION_OVERHEAD_BYTES))
        .ok_or(ReversibleStateDeltaError::SizeOverflow)
}

fn vec_heap_payload_estimate<T>(capacity: usize) -> Result<usize, ReversibleStateDeltaError> {
    if capacity == 0 {
        return Ok(0);
    }
    capacity
        .checked_mul(size_of::<T>())
        .and_then(|bytes| bytes.checked_add(ALLOCATION_OVERHEAD_BYTES))
        .ok_or(ReversibleStateDeltaError::SizeOverflow)
}

fn checked_add(left: usize, right: usize) -> Result<usize, ReversibleStateDeltaError> {
    left.checked_add(right)
        .ok_or(ReversibleStateDeltaError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;

    use super::*;
    use crate::{
        ConsensusPowVerifier, DEFAULT_MONETARY_POLICY, FixedRewardDestinations, PowParameters,
        TEST_PROFILE,
    };

    const SCALAR_PREFIX_BYTES: usize =
        REVERSIBLE_STATE_DELTA_FIXED_BYTES - 3 * DELTA_COUNT_BYTES - DELTA_LOCAL_INTEGRITY_BYTES;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn owner(byte: u8) -> [u8; 32] {
        signing_key(byte).verifying_key().to_bytes().into()
    }

    fn params() -> NetworkParams {
        NetworkParams {
            network_id: [1; 32],
            protocol_version: crate::NETWORK_PROTOCOL_VERSION,
            genesis_hash: [7; 32],
            genesis_timestamp: 0,
            pow_limit: [0xff; 32],
            pow: PowParameters::V1Legacy(TEST_PROFILE),
            monetary_policy: DEFAULT_MONETARY_POLICY,
            rewards: FixedRewardDestinations {
                steward: owner(3),
                community: owner(4),
            },
            max_future_offset_secs: 7_200,
        }
    }

    fn output(value: u64, owner_byte: u8) -> TxOutput {
        TxOutput {
            value,
            lock: OutputLock::Key(owner(owner_byte)),
            spendable_height: 0,
        }
    }

    fn sample_delta(reverse_insertion: bool) -> ReversibleStateDelta {
        let params = params();
        let mut output_entries = vec![
            (
                OutPoint {
                    txid: [1; 32],
                    index: 2,
                },
                OutputChange {
                    previous: Some(output(10, 5)),
                    next: None,
                },
            ),
            (
                OutPoint {
                    txid: [2; 32],
                    index: 1,
                },
                OutputChange {
                    previous: None,
                    next: Some(TxOutput {
                        value: 20,
                        lock: OutputLock::InferenceChannel {
                            channel_id: [9; 32],
                        },
                        spendable_height: 2,
                    }),
                },
            ),
            (
                OutPoint {
                    txid: [3; 32],
                    index: 0,
                },
                OutputChange {
                    previous: Some(output(30, 6)),
                    next: Some(output(25, 7)),
                },
            ),
        ];
        let mut active_entries = vec![
            (
                [0x10; 32],
                MembershipChange {
                    previous: false,
                    next: true,
                },
            ),
            (
                [0x20; 32],
                MembershipChange {
                    previous: true,
                    next: false,
                },
            ),
        ];
        let mut retired_entries = vec![
            (
                [0x30; 32],
                MembershipChange {
                    previous: false,
                    next: true,
                },
            ),
            (
                [0x40; 32],
                MembershipChange {
                    previous: true,
                    next: false,
                },
            ),
        ];
        if reverse_insertion {
            output_entries.reverse();
            active_entries.reverse();
            retired_entries.reverse();
        }

        ReversibleStateDelta {
            network_fingerprint: params.fingerprint().unwrap(),
            base_tip: params.genesis_hash,
            child_tip: [8; 32],
            base_next_height: 1,
            child_next_height: 2,
            base_expected_target: params.pow_limit,
            base_median_time_past: params.genesis_timestamp,
            base_history_len: 1,
            base_timestamp_len: 1,
            fees: 5,
            timestamp: 60,
            effective_timestamp: 60,
            target: params.pow_limit,
            delta: UtxoDelta {
                outputs: output_entries.into_iter().collect(),
                active_channels: active_entries.into_iter().collect(),
                retired_channels: retired_entries.into_iter().collect(),
            },
        }
    }

    fn child_state(delta: &ReversibleStateDelta) -> (ChainState, ChainState) {
        let mut base = ChainState::new(
            params(),
            ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap(),
        )
        .unwrap();
        for (outpoint, change) in &delta.delta.outputs {
            if let Some(output) = &change.previous {
                base.utxos.outputs.insert(*outpoint, output.clone());
            }
        }
        for (channel_id, change) in &delta.delta.active_channels {
            if change.previous {
                base.utxos.active_channels.insert(*channel_id);
            }
        }
        for (channel_id, change) in &delta.delta.retired_channels {
            if change.previous {
                base.utxos.retired_channels.insert(*channel_id);
            }
        }

        let mut child = base.clone();
        delta.delta.clone().apply(&mut child.utxos);
        child.raw_timestamps.push(delta.timestamp);
        child.history.push(HeaderWork {
            timestamp: delta.effective_timestamp,
            target: delta.target,
        });
        child.tip = delta.child_tip;
        child.next_height = delta.child_next_height;
        (base, child)
    }

    fn assert_state_eq(left: &ChainState, right: &ChainState) {
        assert_eq!(left.params, right.params);
        assert_eq!(left.utxos.outputs, right.utxos.outputs);
        assert_eq!(left.utxos.active_channels, right.utxos.active_channels);
        assert_eq!(left.utxos.retired_channels, right.utxos.retired_channels);
        assert_eq!(left.history, right.history);
        assert_eq!(left.raw_timestamps, right.raw_timestamps);
        assert_eq!(left.tip, right.tip);
        assert_eq!(left.next_height, right.next_height);
    }

    fn rebind_local_integrity(bytes: &mut [u8]) {
        let payload_len = bytes.len() - DELTA_LOCAL_INTEGRITY_BYTES;
        let digest = local_integrity_digest(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&digest);
    }

    #[test]
    fn canonical_encoding_ignores_hashmap_insertion_order() {
        let forward = sample_delta(false).encode().unwrap();
        let reverse = sample_delta(true).encode().unwrap();
        assert_eq!(forward, reverse);

        let decoded = DecodedReversibleStateDelta::decode_bound(
            &forward,
            &params(),
            params().genesis_hash,
            [8; 32],
        )
        .unwrap();
        assert_eq!(decoded.delta, sample_delta(false));
    }

    #[test]
    fn every_single_byte_mutation_fails_the_local_integrity_binding() {
        let encoded = sample_delta(false).encode().unwrap();
        for index in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[index] ^= 1;
            assert!(
                DecodedReversibleStateDelta::decode_bound(
                    &mutated,
                    &params(),
                    params().genesis_hash,
                    [8; 32],
                )
                .is_err(),
                "single-byte mutation at offset {index} was accepted"
            );
        }
    }

    #[test]
    fn strict_decoder_rejects_rebound_noncanonical_structures() {
        let encoded = sample_delta(false).encode().unwrap();
        let first_output = SCALAR_PREFIX_BYTES + DELTA_COUNT_BYTES;
        let single_value_change_bytes = OUTPUT_CHANGE_FIXED_BYTES + TX_OUTPUT_BYTES;

        let mut reordered = encoded.clone();
        let second_output = first_output + single_value_change_bytes;
        let two_entries_end = second_output + single_value_change_bytes;
        let mut two_entries = reordered[first_output..two_entries_end].to_vec();
        two_entries.rotate_left(single_value_change_bytes);
        reordered[first_output..two_entries_end].copy_from_slice(&two_entries);
        rebind_local_integrity(&mut reordered);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &reordered,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::NonCanonicalOrder(
                "output change"
            ))
        );

        let mut duplicate = encoded.clone();
        duplicate.copy_within(
            first_output..first_output + single_value_change_bytes,
            second_output,
        );
        rebind_local_integrity(&mut duplicate);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &duplicate,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::NonCanonicalOrder(
                "output change"
            ))
        );

        let mut bad_tag = encoded.clone();
        bad_tag[first_output + OUTPOINT_BYTES] = 2;
        rebind_local_integrity(&mut bad_tag);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &bad_tag,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::InvalidTag {
                field: "optional output",
                tag: 2,
            })
        );

        let replacement = first_output + 2 * single_value_change_bytes;
        let previous_output = replacement + OUTPOINT_BYTES + 1;
        let next_output = previous_output + TX_OUTPUT_BYTES + 1;
        let mut no_op = encoded.clone();
        no_op.copy_within(
            previous_output..previous_output + TX_OUTPUT_BYTES,
            next_output,
        );
        rebind_local_integrity(&mut no_op);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &no_op,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::NoOpChange("output"))
        );

        let mut excessive_count = encoded.clone();
        excessive_count[SCALAR_PREFIX_BYTES..SCALAR_PREFIX_BYTES + DELTA_COUNT_BYTES]
            .copy_from_slice(&u32::try_from(MAX_OUTPUT_CHANGES + 1).unwrap().to_le_bytes());
        rebind_local_integrity(&mut excessive_count);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &excessive_count,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::CountLimit {
                section: "output change",
                actual: MAX_OUTPUT_CHANGES + 1,
                maximum: MAX_OUTPUT_CHANGES,
            })
        );

        let mut trailing = encoded.clone();
        trailing.insert(trailing.len() - DELTA_LOCAL_INTEGRITY_BYTES, 0);
        rebind_local_integrity(&mut trailing);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &trailing,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::TrailingBytes)
        );
    }

    #[test]
    fn decoder_binds_network_and_both_block_ids_and_caps_total_bytes() {
        let encoded = sample_delta(false).encode().unwrap();
        let mut foreign_params = params();
        foreign_params.network_id = [0x55; 32];
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &encoded,
                &foreign_params,
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::BindingMismatch(
                "network fingerprint"
            ))
        );
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(&encoded, &params(), [6; 32], [8; 32]),
            Err(ReversibleStateDeltaError::BindingMismatch("base tip"))
        );
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &encoded,
                &params(),
                params().genesis_hash,
                [9; 32],
            ),
            Err(ReversibleStateDeltaError::BindingMismatch("child tip"))
        );

        let oversized = vec![0; MAX_REVERSIBLE_STATE_DELTA_BYTES + 1];
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &oversized,
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::TooLarge {
                actual: MAX_REVERSIBLE_STATE_DELTA_BYTES + 1,
                maximum: MAX_REVERSIBLE_STATE_DELTA_BYTES,
            })
        );
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &encoded[..REVERSIBLE_STATE_DELTA_FIXED_BYTES - 1],
                &params(),
                params().genesis_hash,
                [8; 32],
            ),
            Err(ReversibleStateDeltaError::Truncated)
        );
    }

    #[test]
    fn structural_validation_rejects_false_header_and_channel_relations() {
        let mut wrong_target = sample_delta(false);
        wrong_target.target[0] ^= 1;
        assert_eq!(
            wrong_target.validate_structure(),
            Err(ReversibleStateDeltaError::InvalidStructure(
                "target transition"
            ))
        );

        let mut stale_timestamp = sample_delta(false);
        stale_timestamp.timestamp = stale_timestamp.base_median_time_past;
        assert_eq!(
            stale_timestamp.validate_structure(),
            Err(ReversibleStateDeltaError::InvalidStructure(
                "timestamp not above median time past"
            ))
        );

        let mut overlapping_membership = sample_delta(false);
        let channel_id = [0x55; 32];
        overlapping_membership.delta.active_channels.insert(
            channel_id,
            MembershipChange {
                previous: true,
                next: false,
            },
        );
        overlapping_membership.delta.retired_channels.insert(
            channel_id,
            MembershipChange {
                previous: true,
                next: false,
            },
        );
        assert_eq!(
            overlapping_membership.validate_structure(),
            Err(ReversibleStateDeltaError::InvalidStructure(
                "simultaneously active and retired channel"
            ))
        );
    }

    #[test]
    fn resource_shaped_maximum_has_an_exact_sub_mib_encoding() {
        let params = params();
        let mut outputs = HashMap::with_capacity(MAX_OUTPUT_CHANGES);
        for index in 0..MAX_OUTPUT_CHANGES {
            let mut txid = [0_u8; 32];
            txid[24..].copy_from_slice(&(index as u64).to_be_bytes());
            let value = TxOutput {
                value: index as u64 + 1,
                lock: OutputLock::Key(owner(5)),
                spendable_height: index as u64,
            };
            let (previous, next) = if index < MAX_BLOCK_AGGREGATE_INPUTS {
                (Some(value), None)
            } else {
                (None, Some(value))
            };
            outputs.insert(OutPoint { txid, index: 0 }, OutputChange { previous, next });
        }
        let active_channels = (0..MAX_ACTIVE_CHANNEL_CHANGES)
            .map(|index| {
                let mut channel_id = [0_u8; 32];
                channel_id[24..].copy_from_slice(&(index as u64).to_be_bytes());
                (
                    channel_id,
                    MembershipChange {
                        previous: false,
                        next: true,
                    },
                )
            })
            .collect();
        let retired_channels = (0..MAX_RETIRED_CHANNEL_CHANGES)
            .map(|index| {
                let mut channel_id = [0xff_u8; 32];
                channel_id[24..].copy_from_slice(&(index as u64).to_be_bytes());
                (
                    channel_id,
                    MembershipChange {
                        previous: true,
                        next: false,
                    },
                )
            })
            .collect();
        let delta = ReversibleStateDelta {
            network_fingerprint: params.fingerprint().unwrap(),
            base_tip: params.genesis_hash,
            child_tip: [8; 32],
            base_next_height: 1,
            child_next_height: 2,
            base_expected_target: params.pow_limit,
            base_median_time_past: 0,
            base_history_len: 1,
            base_timestamp_len: 1,
            fees: 0,
            timestamp: 60,
            effective_timestamp: 60,
            target: params.pow_limit,
            delta: UtxoDelta {
                outputs,
                active_channels,
                retired_channels,
            },
        };

        assert_eq!(MAX_RESOURCE_SHAPED_REVERSIBLE_STATE_DELTA_BYTES, 887_325);
        let encoded = delta.encode().unwrap();
        assert_eq!(
            encoded.len(),
            MAX_RESOURCE_SHAPED_REVERSIBLE_STATE_DELTA_BYTES
        );
        assert!(encoded.len() < MAX_REVERSIBLE_STATE_DELTA_BYTES);
        assert_eq!(
            DecodedReversibleStateDelta::decode_bound(
                &encoded,
                &params,
                params.genesis_hash,
                [8; 32],
            )
            .unwrap()
            .delta,
            delta,
        );
    }

    #[test]
    fn undo_full_preflight_is_atomic_for_scalar_and_late_map_mismatches() {
        let delta = sample_delta(false);
        let (base, child) = child_state(&delta);

        let mut correct = child.clone();
        correct
            .undo_reversible_state_delta(ValidatedReversibleStateDelta(delta.clone()))
            .unwrap();
        assert_state_eq(&correct, &base);

        let mut candidates = Vec::new();
        let mut wrong_tip = child.clone();
        wrong_tip.tip = [0x44; 32];
        candidates.push(wrong_tip);
        let mut wrong_height = child.clone();
        wrong_height.next_height += 1;
        candidates.push(wrong_height);
        let mut wrong_history = child.clone();
        wrong_history.history.last_mut().unwrap().timestamp += 1;
        candidates.push(wrong_history);
        let mut wrong_timestamp = child.clone();
        *wrong_timestamp.raw_timestamps.last_mut().unwrap() += 1;
        candidates.push(wrong_timestamp);
        let mut wrong_output = child.clone();
        let outpoint = *delta.delta.outputs.keys().last().unwrap();
        wrong_output.utxos.outputs.insert(outpoint, output(999, 8));
        candidates.push(wrong_output);
        let mut wrong_active = child.clone();
        let active = *delta.delta.active_channels.keys().last().unwrap();
        if !wrong_active.utxos.active_channels.remove(&active) {
            wrong_active.utxos.active_channels.insert(active);
        }
        candidates.push(wrong_active);
        let mut wrong_retired = child.clone();
        let retired = *delta.delta.retired_channels.keys().last().unwrap();
        if !wrong_retired.utxos.retired_channels.remove(&retired) {
            wrong_retired.utxos.retired_channels.insert(retired);
        }
        candidates.push(wrong_retired);

        for mut candidate in candidates {
            let before = candidate.clone();
            assert_eq!(
                candidate.undo_reversible_state_delta(ValidatedReversibleStateDelta(delta.clone())),
                Err(ReversibleStateDeltaError::StateMismatch)
            );
            assert_state_eq(&candidate, &before);
        }

        let mut forged_effective_delta = delta.clone();
        forged_effective_delta.effective_timestamp = forged_effective_delta
            .effective_timestamp
            .checked_add(1)
            .unwrap();
        let mut forged_effective_child = child.clone();
        forged_effective_child.history.last_mut().unwrap().timestamp =
            forged_effective_delta.effective_timestamp;
        let before = forged_effective_child.clone();
        assert_eq!(
            forged_effective_child.undo_reversible_state_delta(
                ValidatedReversibleStateDelta(forged_effective_delta),
            ),
            Err(ReversibleStateDeltaError::StateMismatch)
        );
        assert_state_eq(&forged_effective_child, &before);

        let mut overlapping_previous_child = child.clone();
        overlapping_previous_child
            .utxos
            .retired_channels
            .insert([0x20; 32]);
        let before = overlapping_previous_child.clone();
        assert_eq!(
            overlapping_previous_child
                .undo_reversible_state_delta(ValidatedReversibleStateDelta(delta),),
            Err(ReversibleStateDeltaError::StateMismatch)
        );
        assert_state_eq(&overlapping_previous_child, &before);
    }

    #[test]
    fn undo_preflight_crosses_median_and_difficulty_window_boundaries() {
        let mut delta = sample_delta(false);
        let mut base = ChainState::new(
            params(),
            ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap(),
        )
        .unwrap();
        base.history = (0..=crate::DGW_WINDOW)
            .map(|index| HeaderWork {
                timestamp: index as u64 * crate::TARGET_SPACING_SECONDS,
                target: base.params.pow_limit,
            })
            .collect();
        base.raw_timestamps = base.history.iter().map(|header| header.timestamp).collect();
        base.next_height = u64::try_from(base.history.len()).unwrap();
        base.tip = [0x77; 32];
        for (outpoint, change) in &delta.delta.outputs {
            if let Some(output) = &change.previous {
                base.utxos.outputs.insert(*outpoint, output.clone());
            }
        }
        for (channel_id, change) in &delta.delta.active_channels {
            if change.previous {
                base.utxos.active_channels.insert(*channel_id);
            }
        }
        for (channel_id, change) in &delta.delta.retired_channels {
            if change.previous {
                base.utxos.retired_channels.insert(*channel_id);
            }
        }

        delta.base_tip = base.tip;
        delta.base_next_height = base.next_height;
        delta.child_next_height = base.next_height + 1;
        delta.base_history_len = u64::try_from(base.history.len()).unwrap();
        delta.base_timestamp_len = u64::try_from(base.raw_timestamps.len()).unwrap();
        delta.base_expected_target = base.expected_target().unwrap();
        delta.base_median_time_past = base.median_time_past();
        delta.timestamp = base.raw_timestamps.last().unwrap() + crate::TARGET_SPACING_SECONDS;
        let window_start = base
            .raw_timestamps
            .len()
            .saturating_sub(crate::MEDIAN_TIME_WINDOW.saturating_sub(1));
        let mut effective_window = base.raw_timestamps[window_start..].to_vec();
        effective_window.push(delta.timestamp);
        delta.effective_timestamp = median_timestamp(&effective_window);
        delta.target = delta.base_expected_target;

        let mut child = base.clone();
        delta.delta.clone().apply(&mut child.utxos);
        child.raw_timestamps.push(delta.timestamp);
        child.history.push(HeaderWork {
            timestamp: delta.effective_timestamp,
            target: delta.target,
        });
        child.tip = delta.child_tip;
        child.next_height = delta.child_next_height;

        child
            .undo_reversible_state_delta(ValidatedReversibleStateDelta(delta))
            .unwrap();
        assert_state_eq(&child, &base);
    }

    #[test]
    fn heap_estimate_is_checked_and_grows_with_owned_state() {
        let mut state = ChainState::new(
            params(),
            ConsensusPowVerifier::v1_legacy(TEST_PROFILE).unwrap(),
        )
        .unwrap();
        let empty_estimate = state.estimated_unique_heap_payload_bytes().unwrap();
        for index in 0..10_000_u64 {
            let mut txid = [0_u8; 32];
            txid[..8].copy_from_slice(&index.to_le_bytes());
            state
                .utxos
                .outputs
                .insert(OutPoint { txid, index: 0 }, output(index + 1, 5));
        }
        assert!(state.estimated_unique_heap_payload_bytes().unwrap() > empty_estimate);
        assert_eq!(
            hash_table_heap_payload_estimate::<OutPoint, TxOutput>(usize::MAX),
            Err(ReversibleStateDeltaError::SizeOverflow)
        );
        assert_eq!(
            vec_heap_payload_estimate::<HeaderWork>(usize::MAX),
            Err(ReversibleStateDeltaError::SizeOverflow)
        );
    }
}
