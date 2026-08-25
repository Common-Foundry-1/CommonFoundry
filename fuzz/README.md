# Consensus and P2P admission fuzzing

These `cargo-fuzz` targets feed untrusted bytes directly to the three bounded
aggregate proof decoders. A panic, sanitizer finding, timeout, or excessive
allocation is a failure; ordinary parser rejection is expected.

The `p2p_admission` target also runs arbitrary peer bytes and deterministic
mutations of canonical `Block` and `SubmitBlock` frames through the public peer
decoder, resource checks, canonical re-encoding, and the current V2 consensus
preverifier. It deliberately creates no node or persistent state, and asserts
that decoded V3 candidates remain rejected by the V2 verifier. Every fuzz input
also drives XOR, boundary truncation, insertion, splice, growth, explicit
outer/block/proof length-field, trailing-byte, and V3 structured-length cases.
A reusable frame at the exact outer peer limit exercises the bounded deep path
without allocating that frame for every input.

```text
cargo +nightly fuzz run structured_aggregate_decode -- "-dict=fuzz/dictionaries/structured.dict" -max_len=262144 -timeout=10
cargo +nightly fuzz run bls_shared_layout_decode -- "-dict=fuzz/dictionaries/bls-shared.dict" -max_len=262128 -timeout=10
cargo +nightly fuzz run bls_v3_candidate_decode -- "-dict=fuzz/dictionaries/bls-v3-candidate.dict" -max_len=261947 -timeout=10
cargo +nightly fuzz run p2p_admission -- "-dict=fuzz/dictionaries/p2p-admission.dict" -max_len=1048596 -timeout=10
```

On Windows, use an MSVC nightly and put Visual Studio's directory containing
`clang_rt.asan_dynamic-x86_64.dll` on `PATH` for the campaign process.

Run campaigns on an isolated development machine. Preserve any discovered
input as a normal deterministic regression test before changing a parser. The
harnesses do not activate the production proof format and do not replace the
required independent review, load testing, or bounded network verification
queue.

CI runs 512 inputs as a bounded sanitizer-backed harness smoke. That smoke
checks the wiring and deterministic mutation modes; it is not a substitute for
a sustained fuzz campaign or completion of a security gate.
