#![no_main]

use cmfd_consensus::{
    BLOCK_KIND as CONSENSUS_BLOCK_KIND, FORGEMATRIX_V4_CANDIDATE_PROOF_TAG,
    PRODUCTION_V4_TESTNET_NETWORK_ID, WIRE_VERSION, network_magic,
};
use cmfd_node::peer::{
    BLOCK_KIND, PEER_MAGIC, PEER_PROTOCOL_VERSION, SUBMIT_BLOCK_KIND, decode_peer_frame,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = decode_peer_frame(bytes, PRODUCTION_V4_TESTNET_NETWORK_ID);

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

    let mut block_payload = Vec::with_capacity(168 + proof.len());
    block_payload.extend_from_slice(&1_u32.to_le_bytes());
    block_payload.extend_from_slice(&PRODUCTION_V4_TESTNET_NETWORK_ID);
    block_payload.extend_from_slice(&[0_u8; 32]);
    block_payload.extend_from_slice(&[0_u8; 32]);
    block_payload.extend_from_slice(&0_u64.to_le_bytes());
    block_payload.extend_from_slice(&0_u64.to_le_bytes());
    block_payload.extend_from_slice(&[0xff_u8; 32]);
    block_payload.extend_from_slice(&proof_length.to_le_bytes());
    block_payload.extend_from_slice(&proof);
    block_payload.extend_from_slice(&0_u64.to_le_bytes());
    block_payload.extend_from_slice(&0_u32.to_le_bytes());
    block_payload.extend_from_slice(&0_u32.to_le_bytes());
    let Some(block_payload_length) = u32::try_from(block_payload.len()).ok() else {
        return;
    };

    let mut block = Vec::with_capacity(16 + block_payload.len());
    block.extend_from_slice(b"CMFD");
    block.extend_from_slice(&network_magic(&PRODUCTION_V4_TESTNET_NETWORK_ID));
    block.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    block.push(CONSENSUS_BLOCK_KIND);
    block.push(0);
    block.extend_from_slice(&block_payload_length.to_le_bytes());
    block.extend_from_slice(&block_payload);
    let Some(block_length) = u32::try_from(block.len()).ok() else {
        return;
    };

    for kind in [BLOCK_KIND, SUBMIT_BLOCK_KIND] {
        let mut peer_frame = Vec::with_capacity(20 + block.len());
        peer_frame.extend_from_slice(&PEER_MAGIC);
        peer_frame.extend_from_slice(&PEER_PROTOCOL_VERSION.to_le_bytes());
        peer_frame.push(kind);
        peer_frame.push(0);
        peer_frame.extend_from_slice(&0_u64.to_le_bytes());
        peer_frame.extend_from_slice(&block_length.to_le_bytes());
        peer_frame.extend_from_slice(&block);
        let _ = decode_peer_frame(&peer_frame, PRODUCTION_V4_TESTNET_NETWORK_ID);
    }
});
