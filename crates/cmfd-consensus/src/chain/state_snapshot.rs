use std::{collections::HashSet, mem::size_of};

use blake3::Hasher;
use thiserror::Error;

use super::{ChainState, HeaderWork, OutPoint, OutputLock, TxOutput, UtxoSet, median_timestamp};
use crate::{
    ConsensusPowVerifier, MEDIAN_TIME_WINDOW, NetworkError, NetworkParams, next_work_target,
};

const SNAPSHOT_MAGIC: [u8; 8] = *b"CMFDCSN\0";
const SNAPSHOT_VERSION: u32 = 1;
const SNAPSHOT_INTEGRITY_DOMAIN: &str = "CMFD/CHAIN-STATE-SNAPSHOT/LOCAL-INTEGRITY/V1";
const SNAPSHOT_FIXED_BYTES: usize =
    SNAPSHOT_MAGIC.len() + size_of::<u32>() + 32 + 32 + size_of::<u64>() + 5 * size_of::<u64>();
const SNAPSHOT_DIGEST_BYTES: usize = 32;
const HEADER_WORK_BYTES: usize = size_of::<u64>() + 32;
const RAW_TIMESTAMP_BYTES: usize = size_of::<u64>();
const UTXO_BYTES: usize = 32 + size_of::<u32>() + size_of::<u64>() + 1 + 32 + size_of::<u64>();
const CHANNEL_BYTES: usize = 32;

/// Hard parser and writer ceiling for a local chain-state snapshot.
///
/// The snapshot is a startup cache, not consensus evidence. A larger state
/// requires a future streaming snapshot revision instead of an unbounded
/// in-memory decode.
pub const MAX_CHAIN_STATE_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainStateSnapshotError {
    #[error("network parameters are invalid: {0}")]
    Network(#[from] NetworkError),
    #[error("proof verifier does not match the snapshot network parameters")]
    PowParameterMismatch,
    #[error("chain-state snapshot exceeds the {maximum}-byte limit")]
    TooLarge { maximum: usize },
    #[error("chain-state snapshot ended before all canonical fields were decoded")]
    Truncated,
    #[error("chain-state snapshot has an invalid magic value")]
    InvalidMagic,
    #[error("unsupported chain-state snapshot version {0}")]
    UnsupportedVersion(u32),
    #[error("chain-state snapshot belongs to another network")]
    WrongNetwork,
    #[error("chain-state snapshot failed its local integrity binding")]
    IntegrityMismatch,
    #[error("chain-state snapshot has a noncanonical {0}")]
    NonCanonical(&'static str),
    #[error("chain-state snapshot contains invalid {0}")]
    InvalidState(&'static str),
    #[error("chain-state snapshot size calculation overflowed")]
    SizeOverflow,
}

impl ChainState {
    /// Encodes a canonical, network-bound local startup snapshot.
    ///
    /// The trailing digest detects accidental corruption. It is deliberately
    /// not a consensus state root and does not protect against an attacker who
    /// can replace both node storage and this local cache.
    pub fn encode_local_snapshot(&self) -> Result<Vec<u8>, ChainStateSnapshotError> {
        validate_snapshot_state(self)?;

        let mut outputs: Vec<_> = self.utxos.outputs.iter().collect();
        outputs.sort_unstable_by(|(left, _), (right, _)| compare_outpoints(left, right));
        let mut active_channels: Vec<_> = self.utxos.active_channels.iter().copied().collect();
        active_channels.sort_unstable();
        let mut retired_channels: Vec<_> = self.utxos.retired_channels.iter().copied().collect();
        retired_channels.sort_unstable();

        let encoded_len = snapshot_encoded_len(
            self.history.len(),
            self.raw_timestamps.len(),
            outputs.len(),
            active_channels.len(),
            retired_channels.len(),
        )?;
        if encoded_len > MAX_CHAIN_STATE_SNAPSHOT_BYTES {
            return Err(ChainStateSnapshotError::TooLarge {
                maximum: MAX_CHAIN_STATE_SNAPSHOT_BYTES,
            });
        }

        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.params.fingerprint()?);
        bytes.extend_from_slice(&self.tip);
        bytes.extend_from_slice(&self.next_height.to_le_bytes());
        write_count(&mut bytes, self.history.len())?;
        write_count(&mut bytes, self.raw_timestamps.len())?;
        write_count(&mut bytes, outputs.len())?;
        write_count(&mut bytes, active_channels.len())?;
        write_count(&mut bytes, retired_channels.len())?;
        for header in &self.history {
            bytes.extend_from_slice(&header.timestamp.to_le_bytes());
            bytes.extend_from_slice(&header.target);
        }
        for timestamp in &self.raw_timestamps {
            bytes.extend_from_slice(&timestamp.to_le_bytes());
        }
        for (outpoint, output) in outputs {
            bytes.extend_from_slice(&outpoint.txid);
            bytes.extend_from_slice(&outpoint.index.to_le_bytes());
            bytes.extend_from_slice(&output.value.to_le_bytes());
            match output.lock {
                OutputLock::Key(key) => {
                    bytes.push(0);
                    bytes.extend_from_slice(&key);
                }
                OutputLock::InferenceChannel { channel_id } => {
                    bytes.push(1);
                    bytes.extend_from_slice(&channel_id);
                }
            }
            bytes.extend_from_slice(&output.spendable_height.to_le_bytes());
        }
        for channel_id in active_channels {
            bytes.extend_from_slice(&channel_id);
        }
        for channel_id in retired_channels {
            bytes.extend_from_slice(&channel_id);
        }
        let digest = snapshot_digest(&bytes);
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    /// Restores a structurally validated local snapshot for the exact network.
    ///
    /// Callers must separately bind these bytes to authenticated node storage;
    /// successful decoding alone never authorizes skipping block validation.
    pub fn decode_local_snapshot(
        bytes: &[u8],
        params: NetworkParams,
        verifier: ConsensusPowVerifier,
    ) -> Result<Self, ChainStateSnapshotError> {
        if bytes.len() > MAX_CHAIN_STATE_SNAPSHOT_BYTES {
            return Err(ChainStateSnapshotError::TooLarge {
                maximum: MAX_CHAIN_STATE_SNAPSHOT_BYTES,
            });
        }
        if bytes.len() < SNAPSHOT_FIXED_BYTES + SNAPSHOT_DIGEST_BYTES {
            return Err(ChainStateSnapshotError::Truncated);
        }
        params.validate_for_bound_verifier()?;
        if verifier.parameters() != params.pow {
            return Err(ChainStateSnapshotError::PowParameterMismatch);
        }
        let (payload, expected_digest) = bytes.split_at(bytes.len() - SNAPSHOT_DIGEST_BYTES);
        if snapshot_digest(payload) != expected_digest {
            return Err(ChainStateSnapshotError::IntegrityMismatch);
        }

        let mut decoder = Decoder::new(payload);
        if decoder.array::<8>()? != SNAPSHOT_MAGIC {
            return Err(ChainStateSnapshotError::InvalidMagic);
        }
        let version = decoder.u32()?;
        if version != SNAPSHOT_VERSION {
            return Err(ChainStateSnapshotError::UnsupportedVersion(version));
        }
        if decoder.array::<32>()? != params.fingerprint()? {
            return Err(ChainStateSnapshotError::WrongNetwork);
        }
        let tip = decoder.array::<32>()?;
        let next_height = decoder.u64()?;
        let history_count = decoder.count()?;
        let timestamp_count = decoder.count()?;
        let output_count = decoder.count()?;
        let active_count = decoder.count()?;
        let retired_count = decoder.count()?;
        let expected_len = snapshot_encoded_len(
            history_count,
            timestamp_count,
            output_count,
            active_count,
            retired_count,
        )?
        .checked_sub(SNAPSHOT_DIGEST_BYTES)
        .ok_or(ChainStateSnapshotError::SizeOverflow)?;
        if expected_len != payload.len() {
            return Err(ChainStateSnapshotError::InvalidState("encoded length"));
        }

        let mut history = Vec::with_capacity(history_count);
        for _ in 0..history_count {
            history.push(HeaderWork {
                timestamp: decoder.u64()?,
                target: decoder.array::<32>()?,
            });
        }
        let mut raw_timestamps = Vec::with_capacity(timestamp_count);
        for _ in 0..timestamp_count {
            raw_timestamps.push(decoder.u64()?);
        }
        let mut utxos = UtxoSet::default();
        let mut previous_outpoint = None;
        for _ in 0..output_count {
            let outpoint = OutPoint {
                txid: decoder.array::<32>()?,
                index: decoder.u32()?,
            };
            if previous_outpoint
                .as_ref()
                .is_some_and(|previous| compare_outpoints(previous, &outpoint).is_ge())
            {
                return Err(ChainStateSnapshotError::NonCanonical("UTXO order"));
            }
            previous_outpoint = Some(outpoint);
            let value = decoder.u64()?;
            let lock_tag = decoder.byte()?;
            let lock_value = decoder.array::<32>()?;
            let lock = match lock_tag {
                0 => OutputLock::Key(lock_value),
                1 => OutputLock::InferenceChannel {
                    channel_id: lock_value,
                },
                _ => return Err(ChainStateSnapshotError::NonCanonical("output lock tag")),
            };
            let output = TxOutput {
                value,
                lock,
                spendable_height: decoder.u64()?,
            };
            if utxos.outputs.insert(outpoint, output).is_some() {
                return Err(ChainStateSnapshotError::NonCanonical("duplicate UTXO"));
            }
        }
        let active_channels = decode_channels(&mut decoder, active_count, "active channel order")?;
        let retired_channels =
            decode_channels(&mut decoder, retired_count, "retired channel order")?;
        if !decoder.is_empty() {
            return Err(ChainStateSnapshotError::InvalidState("trailing bytes"));
        }
        utxos.active_channels = active_channels;
        utxos.retired_channels = retired_channels;

        let state = Self {
            params,
            utxos,
            history,
            raw_timestamps,
            tip,
            next_height,
            verifier,
        };
        validate_snapshot_state(&state)?;
        if state.encode_local_snapshot()?.as_slice() != bytes {
            return Err(ChainStateSnapshotError::NonCanonical("encoding"));
        }
        Ok(state)
    }
}

fn validate_snapshot_state(state: &ChainState) -> Result<(), ChainStateSnapshotError> {
    state.params.validate_for_bound_verifier()?;
    if state.verifier.parameters() != state.params.pow {
        return Err(ChainStateSnapshotError::PowParameterMismatch);
    }
    let height = usize::try_from(state.next_height)
        .map_err(|_| ChainStateSnapshotError::InvalidState("height"))?;
    if height == 0
        || state.history.len() != height
        || state.raw_timestamps.len() != height
        || state.history.first()
            != Some(&HeaderWork {
                timestamp: state.params.genesis_timestamp,
                target: state.params.initial_work_target(),
            })
        || state.raw_timestamps.first() != Some(&state.params.genesis_timestamp)
    {
        return Err(ChainStateSnapshotError::InvalidState("history shape"));
    }
    if (height == 1) != (state.tip == state.params.genesis_hash) {
        return Err(ChainStateSnapshotError::InvalidState("tip"));
    }
    for index in 1..height {
        let prior_median = median_timestamp(&state.raw_timestamps[..index]);
        if state.raw_timestamps[index] <= prior_median {
            return Err(ChainStateSnapshotError::InvalidState("timestamp history"));
        }
        let window_start = index.saturating_sub(MEDIAN_TIME_WINDOW.saturating_sub(1));
        let effective = median_timestamp(&state.raw_timestamps[window_start..=index]);
        if state.history[index].timestamp != effective
            || state.history[index].target
                != next_work_target(&state.history[..index], state.params.pow_limit)
                    .map_err(|_| ChainStateSnapshotError::InvalidState("difficulty history"))?
        {
            return Err(ChainStateSnapshotError::InvalidState("header history"));
        }
    }
    if state.utxos.outputs.values().any(|output| output.value == 0) {
        return Err(ChainStateSnapshotError::InvalidState("zero-value output"));
    }
    if !state
        .utxos
        .active_channels
        .is_disjoint(&state.utxos.retired_channels)
    {
        return Err(ChainStateSnapshotError::InvalidState("channel membership"));
    }
    let output_channels: HashSet<_> = state
        .utxos
        .outputs
        .values()
        .filter_map(|output| match output.lock {
            OutputLock::InferenceChannel { channel_id } => Some(channel_id),
            OutputLock::Key(_) => None,
        })
        .collect();
    if output_channels.len() != state.utxos.active_channels.len()
        || output_channels != state.utxos.active_channels
    {
        return Err(ChainStateSnapshotError::InvalidState(
            "active channel outputs",
        ));
    }
    Ok(())
}

fn compare_outpoints(left: &OutPoint, right: &OutPoint) -> std::cmp::Ordering {
    left.txid
        .cmp(&right.txid)
        .then_with(|| left.index.cmp(&right.index))
}

fn decode_channels(
    decoder: &mut Decoder<'_>,
    count: usize,
    ordering: &'static str,
) -> Result<HashSet<[u8; 32]>, ChainStateSnapshotError> {
    let mut channels = HashSet::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let channel = decoder.array::<32>()?;
        if previous.is_some_and(|previous| previous >= channel) {
            return Err(ChainStateSnapshotError::NonCanonical(ordering));
        }
        previous = Some(channel);
        channels.insert(channel);
    }
    Ok(channels)
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), ChainStateSnapshotError> {
    let count = u64::try_from(count).map_err(|_| ChainStateSnapshotError::SizeOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn snapshot_encoded_len(
    history: usize,
    timestamps: usize,
    outputs: usize,
    active_channels: usize,
    retired_channels: usize,
) -> Result<usize, ChainStateSnapshotError> {
    let sections = [
        (history, HEADER_WORK_BYTES),
        (timestamps, RAW_TIMESTAMP_BYTES),
        (outputs, UTXO_BYTES),
        (active_channels, CHANNEL_BYTES),
        (retired_channels, CHANNEL_BYTES),
    ];
    sections.into_iter().try_fold(
        SNAPSHOT_FIXED_BYTES + SNAPSHOT_DIGEST_BYTES,
        |total, (count, width)| {
            count
                .checked_mul(width)
                .and_then(|section| total.checked_add(section))
                .ok_or(ChainStateSnapshotError::SizeOverflow)
        },
    )
}

fn snapshot_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SNAPSHOT_INTEGRITY_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ChainStateSnapshotError> {
        if self.remaining.len() < length {
            return Err(ChainStateSnapshotError::Truncated);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ChainStateSnapshotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChainStateSnapshotError::Truncated)
    }

    fn byte(&mut self) -> Result<u8, ChainStateSnapshotError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, ChainStateSnapshotError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ChainStateSnapshotError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, ChainStateSnapshotError> {
        usize::try_from(self.u64()?).map_err(|_| ChainStateSnapshotError::SizeOverflow)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockValidationContext;
    use crate::chain::tests::{
        block_for_state, legacy_verifier, miner_destination, network_params,
    };

    #[test]
    fn local_snapshot_round_trips_canonically() {
        let params = network_params();
        let verifier = legacy_verifier();
        let mut state = ChainState::new(params, verifier.clone()).unwrap();
        let block = block_for_state(&state, 60, miner_destination(), Vec::new(), 0, 0);
        state
            .validate_and_apply(
                &block,
                BlockValidationContext {
                    now_unix_seconds: 60,
                },
            )
            .unwrap();

        let encoded = state.encode_local_snapshot().unwrap();
        let decoded = ChainState::decode_local_snapshot(&encoded, params, verifier).unwrap();
        assert_eq!(decoded.tip, state.tip);
        assert_eq!(decoded.next_height, state.next_height);
        assert_eq!(decoded.history, state.history);
        assert_eq!(decoded.raw_timestamps, state.raw_timestamps);
        assert_eq!(decoded.utxos.outputs, state.utxos.outputs);
        assert_eq!(decoded.encode_local_snapshot().unwrap(), encoded);

        let successor = state.successor_header_preflight().unwrap();
        let encoded_successor = successor.encode_local_snapshot().unwrap();
        assert_eq!(
            super::super::SuccessorHeaderPreflight::decode_local_snapshot(
                &encoded_successor,
                params,
            )
            .unwrap(),
            successor,
        );
    }

    #[test]
    fn local_snapshot_rejects_corruption_network_and_trailing_bytes() {
        let params = network_params();
        let verifier = legacy_verifier();
        let state = ChainState::new(params, verifier.clone()).unwrap();
        let encoded = state.encode_local_snapshot().unwrap();

        let mut corrupt = encoded.clone();
        corrupt[SNAPSHOT_FIXED_BYTES] ^= 1;
        assert!(matches!(
            ChainState::decode_local_snapshot(&corrupt, params, verifier.clone()),
            Err(ChainStateSnapshotError::IntegrityMismatch)
        ));

        let mut wrong_params = params;
        wrong_params.network_id[0] ^= 1;
        assert!(matches!(
            ChainState::decode_local_snapshot(&encoded, wrong_params, verifier.clone()),
            Err(ChainStateSnapshotError::WrongNetwork)
                | Err(ChainStateSnapshotError::Network(_))
                | Err(ChainStateSnapshotError::PowParameterMismatch)
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            ChainState::decode_local_snapshot(&trailing, params, verifier),
            Err(ChainStateSnapshotError::IntegrityMismatch)
        ));
    }
}
