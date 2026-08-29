#![no_main]

use cmfd_consensus::{
    FORGEMATRIX_PROOF_KIND, FORGEMATRIX_V4_CANDIDATE_PROOF_TAG, PRODUCTION_V4_TESTNET_NETWORK_ID,
    WIRE_VERSION, decode_forgematrix_proof, network_magic,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = decode_forgematrix_proof(bytes, PRODUCTION_V4_TESTNET_NETWORK_ID);

    let transparent_proof = if bytes.is_empty() { &[0_u8][..] } else { bytes };
    let Some(proof_length) = u32::try_from(transparent_proof.len()).ok() else {
        return;
    };
    let mut payload = Vec::with_capacity(213 + transparent_proof.len());
    payload.push(FORGEMATRIX_V4_CANDIDATE_PROOF_TAG);
    payload.extend_from_slice(&PRODUCTION_V4_TESTNET_NETWORK_ID);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&0_u64.to_le_bytes());
    payload.extend_from_slice(&[0_u8; 5 * 32]);
    payload.extend_from_slice(&proof_length.to_le_bytes());
    payload.extend_from_slice(transparent_proof);

    let Some(payload_length) = u32::try_from(payload.len()).ok() else {
        return;
    };
    let mut frame = Vec::with_capacity(16 + payload.len());
    frame.extend_from_slice(b"CMFD");
    frame.extend_from_slice(&network_magic(&PRODUCTION_V4_TESTNET_NETWORK_ID));
    frame.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    frame.push(FORGEMATRIX_PROOF_KIND);
    frame.push(0);
    frame.extend_from_slice(&payload_length.to_le_bytes());
    frame.extend_from_slice(&payload);
    let _ = decode_forgematrix_proof(&frame, PRODUCTION_V4_TESTNET_NETWORK_ID);
});
