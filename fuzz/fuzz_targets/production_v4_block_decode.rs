#![no_main]

use cmfd_consensus::{
    BLOCK_KIND, FORGEMATRIX_V4_CANDIDATE_PROOF_TAG, PRODUCTION_V4_TESTNET_NETWORK_ID, WIRE_VERSION,
    decode_block, network_magic,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = decode_block(bytes, PRODUCTION_V4_TESTNET_NETWORK_ID);

    let transparent_proof = if bytes.is_empty() { &[0_u8][..] } else { bytes };
    let Some(transparent_length) = u32::try_from(transparent_proof.len()).ok() else {
        return;
    };
    let mut proof = Vec::with_capacity(213 + transparent_proof.len());
    proof.push(FORGEMATRIX_V4_CANDIDATE_PROOF_TAG);
    proof.extend_from_slice(&PRODUCTION_V4_TESTNET_NETWORK_ID);
    proof.extend_from_slice(&1_u32.to_le_bytes());
    proof.extend_from_slice(&1_u32.to_le_bytes());
    proof.extend_from_slice(&0_u64.to_le_bytes());
    proof.extend_from_slice(&[0_u8; 5 * 32]);
    proof.extend_from_slice(&transparent_length.to_le_bytes());
    proof.extend_from_slice(transparent_proof);
    let Some(proof_length) = u32::try_from(proof.len()).ok() else {
        return;
    };

    let mut payload = Vec::with_capacity(168 + proof.len());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&PRODUCTION_V4_TESTNET_NETWORK_ID);
    payload.extend_from_slice(&[0_u8; 32]);
    payload.extend_from_slice(&[0_u8; 32]);
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&[0xff_u8; 32]);
    payload.extend_from_slice(&proof_length.to_le_bytes());
    payload.extend_from_slice(&proof);
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());

    let Some(payload_length) = u32::try_from(payload.len()).ok() else {
        return;
    };
    let mut frame = Vec::with_capacity(16 + payload.len());
    frame.extend_from_slice(b"CMFD");
    frame.extend_from_slice(&network_magic(&PRODUCTION_V4_TESTNET_NETWORK_ID));
    frame.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    frame.push(BLOCK_KIND);
    frame.push(0);
    frame.extend_from_slice(&payload_length.to_le_bytes());
    frame.extend_from_slice(&payload);
    let _ = decode_block(&frame, PRODUCTION_V4_TESTNET_NETWORK_ID);
});
