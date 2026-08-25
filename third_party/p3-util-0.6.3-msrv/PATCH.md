# p3-util 0.6.3 Rust 1.88 compatibility patch

This directory vendors the source published as `p3-util` version `0.6.3`.
Its `src/lib.rs` SHA-256 before modification was
`fea5edfb568694917ffcd8bfc0973b250c9f7bba4ff36a1f84cd9a899c6f2698`.

The only functional change restores the slice conversion used by upstream
`p3-util` before it adopted `slice::assume_init_ref`. The standard-library API
stabilized after Common Foundry's Rust 1.88 minimum, while the former conversion
has the same safety precondition and result.

Upstream: <https://github.com/Plonky3/Plonky3>

Package release: `p3-util 0.6.3`

License: MIT OR Apache-2.0. Common Foundry redistributes this copy under MIT;
see `LICENSE-MIT` in this directory.
