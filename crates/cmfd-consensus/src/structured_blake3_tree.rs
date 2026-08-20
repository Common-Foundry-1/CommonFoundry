//! Exact BLAKE3 tree schedule used by the narrow production hash argument.
//!
//! This module deliberately keeps tree construction separate from the proof
//! backend.  The schedule is deterministic for a message length, and witness
//! generation is checked against the upstream `blake3` implementation before
//! any trace is committed.

use std::array;

use thiserror::Error;

const BLOCK_BYTES: usize = 64;
const CHUNK_BYTES: usize = 1024;
const PUBLIC_PREFIX_BYTES: usize = 40;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Blake3TreeError {
    #[error("BLAKE3 tree activation length must be a nonzero power of two")]
    InvalidActivationLength,
    #[error("BLAKE3 tree activation contains a noncanonical byte")]
    ActivationEncoding,
    #[error("BLAKE3 tree schedule overflowed")]
    ArithmeticOverflow,
    #[error("BLAKE3 tree witness does not match the upstream implementation")]
    DigestMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompressionKind {
    Chunk,
    Parent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompressionOp {
    pub kind: CompressionKind,
    pub block: [u32; 16],
    pub chaining_value: [u32; 8],
    pub counter: u64,
    pub block_len: u32,
    pub flags: u32,
    pub output: [u32; 16],
    pub output_id: Option<u32>,
    pub consume_left: Option<u32>,
    pub consume_right: Option<u32>,
    pub message_offset: Option<usize>,
    pub stack_read_left: Option<usize>,
    pub stack_read_right: Option<usize>,
    pub stack_write: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blake3TreeWitness {
    pub operations: Vec<CompressionOp>,
    pub digest: [u8; 32],
    pub message_len: usize,
    pub chunk_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct Node {
    id: u32,
    cv: [u32; 8],
    chunks: usize,
}

pub(crate) fn build_tree_witness(
    output_context: &str,
    challenge: [u8; 32],
    activation: &[u8],
) -> Result<Blake3TreeWitness, Blake3TreeError> {
    validate_activation(activation)?;
    let message = output_message(challenge, activation)?;
    let context_key = blake3::hazmat::hash_derive_key_context(output_context);
    let key_words = bytes_to_words_8(&context_key);
    let chunk_count = message.len().div_ceil(CHUNK_BYTES);
    let mut operations = Vec::new();
    let mut next_id = 1_u32;
    let mut stack = Vec::with_capacity(chunk_count.ilog2() as usize + 2);

    for (chunk_index, chunk) in message.chunks(CHUNK_BYTES).enumerate() {
        let mut cv = key_words;
        let block_count = chunk.len().div_ceil(BLOCK_BYTES);
        let mut previous_id = None;
        for block_index in 0..block_count {
            let start = block_index * BLOCK_BYTES;
            let end = (start + BLOCK_BYTES).min(chunk.len());
            let mut block_bytes = [0_u8; BLOCK_BYTES];
            block_bytes[..end - start].copy_from_slice(&chunk[start..end]);
            let block = bytes_to_words_16(&block_bytes);
            let is_last = block_index + 1 == block_count;
            let is_root = chunk_count == 1 && is_last;
            let mut flags = DERIVE_KEY_MATERIAL;
            if block_index == 0 {
                flags |= CHUNK_START;
            }
            if is_last {
                flags |= CHUNK_END;
            }
            if is_root {
                flags |= ROOT;
            }
            let output = compress(cv, block, chunk_index as u64, (end - start) as u32, flags);
            let output_id = if is_root {
                None
            } else {
                let id = next_id;
                next_id = next_id
                    .checked_add(1)
                    .ok_or(Blake3TreeError::ArithmeticOverflow)?;
                Some(id)
            };
            operations.push(CompressionOp {
                kind: CompressionKind::Chunk,
                block,
                chaining_value: cv,
                counter: chunk_index as u64,
                block_len: (end - start) as u32,
                flags,
                output,
                output_id,
                consume_left: previous_id,
                consume_right: None,
                message_offset: Some(chunk_index * CHUNK_BYTES + start),
                stack_read_left: None,
                stack_read_right: None,
                stack_write: None,
            });
            cv.copy_from_slice(&output[..8]);
            previous_id = output_id;
        }
        if chunk_count > 1 {
            let stack_slot = stack.len();
            operations
                .last_mut()
                .expect("chunk has a final compression")
                .stack_write = Some(stack_slot);
            stack.push(Node {
                id: previous_id.expect("non-root chunk has an output id"),
                cv,
                chunks: 1,
            });
            while stack.len() >= 2 && stack[stack.len() - 1].chunks == stack[stack.len() - 2].chunks
            {
                let is_root = chunk_index + 1 == chunk_count && stack.len() == 2;
                merge_stack_nodes(
                    &mut operations,
                    &mut next_id,
                    key_words,
                    &mut stack,
                    is_root,
                )?;
            }
        }
    }

    let digest = if chunk_count == 1 {
        output_words(
            &operations
                .last()
                .expect("one chunk has an operation")
                .output,
        )
    } else {
        while stack.len() > 1 {
            let is_root = stack.len() == 2;
            merge_stack_nodes(
                &mut operations,
                &mut next_id,
                key_words,
                &mut stack,
                is_root,
            )?;
        }
        output_words(&operations.last().expect("tree has a root operation").output)
    };

    let expected = crate::forgematrix_v2::output_digest(challenge, activation);
    if digest != expected {
        return Err(Blake3TreeError::DigestMismatch);
    }
    Ok(Blake3TreeWitness {
        operations,
        digest,
        message_len: message.len(),
        chunk_count,
    })
}

fn merge_stack_nodes(
    operations: &mut Vec<CompressionOp>,
    next_id: &mut u32,
    key_words: [u32; 8],
    stack: &mut Vec<Node>,
    is_root: bool,
) -> Result<(), Blake3TreeError> {
    let right_slot = stack
        .len()
        .checked_sub(1)
        .ok_or(Blake3TreeError::ArithmeticOverflow)?;
    let left_slot = right_slot
        .checked_sub(1)
        .ok_or(Blake3TreeError::ArithmeticOverflow)?;
    let right = stack.pop().expect("right stack node exists");
    let left = stack.pop().expect("left stack node exists");
    let mut block = [0_u32; 16];
    block[..8].copy_from_slice(&left.cv);
    block[8..].copy_from_slice(&right.cv);
    let flags = DERIVE_KEY_MATERIAL | PARENT | if is_root { ROOT } else { 0 };
    let output = compress(key_words, block, 0, BLOCK_BYTES as u32, flags);
    let output_id = if is_root {
        None
    } else {
        let id = *next_id;
        *next_id = next_id
            .checked_add(1)
            .ok_or(Blake3TreeError::ArithmeticOverflow)?;
        Some(id)
    };
    operations.push(CompressionOp {
        kind: CompressionKind::Parent,
        block,
        chaining_value: key_words,
        counter: 0,
        block_len: BLOCK_BYTES as u32,
        flags,
        output,
        output_id,
        consume_left: Some(left.id),
        consume_right: Some(right.id),
        message_offset: None,
        stack_read_left: Some(left_slot),
        stack_read_right: Some(right_slot),
        stack_write: if is_root { None } else { Some(left_slot) },
    });
    if !is_root {
        stack.push(Node {
            id: output_id.unwrap_or(0),
            cv: output[..8].try_into().expect("eight chaining words"),
            chunks: left
                .chunks
                .checked_add(right.chunks)
                .ok_or(Blake3TreeError::ArithmeticOverflow)?,
        });
    }
    Ok(())
}

fn validate_activation(activation: &[u8]) -> Result<(), Blake3TreeError> {
    if activation.is_empty() || !activation.len().is_power_of_two() {
        return Err(Blake3TreeError::InvalidActivationLength);
    }
    if activation.iter().any(|value| *value > 250) {
        return Err(Blake3TreeError::ActivationEncoding);
    }
    Ok(())
}

fn output_message(challenge: [u8; 32], activation: &[u8]) -> Result<Vec<u8>, Blake3TreeError> {
    let length =
        u64::try_from(activation.len()).map_err(|_| Blake3TreeError::ArithmeticOverflow)?;
    let capacity = PUBLIC_PREFIX_BYTES
        .checked_add(activation.len())
        .ok_or(Blake3TreeError::ArithmeticOverflow)?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(&challenge);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(activation);
    Ok(message)
}

fn compress(
    chaining_value: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut message = block;
    for _ in 0..7 {
        round(&mut state, &message);
        message = array::from_fn(|index| message[MSG_PERMUTATION[index]]);
    }
    array::from_fn(|index| {
        if index < 8 {
            state[index] ^ state[index + 8]
        } else {
            state[index] ^ chaining_value[index - 8]
        }
    })
}

fn round(state: &mut [u32; 16], message: &[u32; 16]) {
    for index in 0..4 {
        g(
            state,
            index,
            4 + index,
            8 + index,
            12 + index,
            message[2 * index],
            message[2 * index + 1],
        );
    }
    for index in 0..4 {
        g(
            state,
            index,
            4 + (index + 1) % 4,
            8 + (index + 2) % 4,
            12 + (index + 3) % 4,
            message[8 + 2 * index],
            message[9 + 2 * index],
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn bytes_to_words_8(bytes: &[u8; 32]) -> [u32; 8] {
    array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..(index + 1) * 4].try_into().expect("word"))
    })
}

fn bytes_to_words_16(bytes: &[u8; 64]) -> [u32; 16] {
    array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..(index + 1) * 4].try_into().expect("word"))
    })
}

fn output_words(output: &[u32; 16]) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    for (index, word) in output[..8].iter().enumerate() {
        digest[index * 4..(index + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT_CONTEXT: &str = "CMFD/FORGEMATRIX/OUTPUT/V2";

    #[test]
    fn schedule_matches_upstream_across_chunk_boundaries() {
        for length in [1, 8, 64, 512, 1024, 2048, 4096] {
            let activation = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let witness = build_tree_witness(OUTPUT_CONTEXT, [0x42; 32], &activation).unwrap();
            assert_eq!(
                witness.digest,
                crate::forgematrix_v2::output_digest([0x42; 32], &activation)
            );
            assert_eq!(witness.message_len, PUBLIC_PREFIX_BYTES + length);
            assert_eq!(
                witness.chunk_count,
                witness.message_len.div_ceil(CHUNK_BYTES)
            );
            assert_eq!(
                witness.operations.len(),
                witness.message_len.div_ceil(BLOCK_BYTES) + witness.chunk_count.saturating_sub(1)
            );
        }
    }

    #[test]
    fn production_schedule_has_exact_shape_and_root() {
        let activation = (0..(1 << 19))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let witness = build_tree_witness(OUTPUT_CONTEXT, [0x24; 32], &activation).unwrap();
        assert_eq!(witness.message_len, 524_328);
        assert_eq!(witness.chunk_count, 513);
        assert_eq!(witness.operations.len(), 8_705);
        let highest_stack_slot = witness
            .operations
            .iter()
            .flat_map(|operation| {
                [
                    operation.stack_read_left,
                    operation.stack_read_right,
                    operation.stack_write,
                ]
                .into_iter()
                .flatten()
            })
            .max()
            .unwrap();
        assert_eq!(highest_stack_slot, 9);
        let root = witness.operations.last().unwrap();
        assert_eq!(root.kind, CompressionKind::Parent);
        assert_eq!(root.flags, DERIVE_KEY_MATERIAL | PARENT | ROOT);
        assert_eq!(root.output_id, None);
        assert_eq!(
            witness.digest,
            crate::forgematrix_v2::output_digest([0x24; 32], &activation)
        );
    }

    #[test]
    fn invalid_activation_is_rejected() {
        assert_eq!(
            build_tree_witness(OUTPUT_CONTEXT, [0; 32], &[]),
            Err(Blake3TreeError::InvalidActivationLength)
        );
        assert_eq!(
            build_tree_witness(OUTPUT_CONTEXT, [0; 32], &[251]),
            Err(Blake3TreeError::ActivationEncoding)
        );
    }
}
