# Linux wallet dependency regression

This small standalone test links the same locally patched GLib 0.18.5 selected
by the wallet's workspace dependency graph. Run it with optimization enabled:

```sh
cargo test --locked --release --manifest-path tools/linux-wallet-dependency-check/Cargo.toml
```

It exercises `VariantStrIter` traversal, empty arrays and Unicode without
creating a wallet, starting a node, contacting a network or using a GPU.
The unpatched 0.18.5 iterator crashed under the same optimized Rust 1.94.1 test.
GLib development libraries are required (already needed by the Linux wallet).
This is a focused library regression, not a substitute for native-wallet QA.
