# Consensus parser fuzzing

These `cargo-fuzz` targets feed untrusted bytes directly to the bounded
aggregate proof decoders and the ProductionV4 wire proof and block decoders.
A panic, sanitizer finding, timeout, or excessive allocation is a failure;
ordinary parser rejection is expected.

```text
cargo +nightly fuzz run structured_aggregate_decode -- "-dict=fuzz/dictionaries/structured.dict" -max_len=262144 -timeout=10
cargo +nightly fuzz run bls_shared_layout_decode -- "-dict=fuzz/dictionaries/bls-shared.dict" -max_len=262128 -timeout=10
cargo +nightly fuzz run bls_v3_candidate_decode -- "-dict=fuzz/dictionaries/bls-v3-candidate.dict" -max_len=261947 -timeout=10
cargo +nightly fuzz run production_v4_proof_decode -- "-dict=fuzz/dictionaries/production-v4-wire.dict" -max_len=13631489 -timeout=10 -rss_limit_mb=4096 -malloc_limit_mb=1024
cargo +nightly fuzz run production_v4_block_decode -- "-dict=fuzz/dictionaries/production-v4-wire.dict" -max_len=16777217 -timeout=10 -rss_limit_mb=4096 -malloc_limit_mb=1024
```

On Windows, use an MSVC nightly and put Visual Studio's directory containing
`clang_rt.asan_dynamic-x86_64.dll` on `PATH` for the campaign process.

Run campaigns on an isolated development machine. Preserve any discovered
input as a normal deterministic regression test before changing a parser. The
harnesses do not activate a mainnet proof format and do not replace the
required independent review, load testing, or bounded network verification
queue.
