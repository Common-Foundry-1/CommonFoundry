#![no_main]

use cmfd_node::pool::fuzz_decode_pool_frames;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    fuzz_decode_pool_frames(bytes);
});
