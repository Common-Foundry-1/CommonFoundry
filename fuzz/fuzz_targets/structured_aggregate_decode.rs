#![no_main]

use cmfd_consensus::StructuredForgeMatrixProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = StructuredForgeMatrixProof::decode(bytes);
});
