#![no_main]

use cmfd_consensus::dory_bls12_381_candidate::BlsDoryV3CandidatePayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = BlsDoryV3CandidatePayload::decode(bytes);
});
