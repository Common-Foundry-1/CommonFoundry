# GLib 0.18.5: VariantStrIter upstream backport

This starts from the exact published `glib` 0.18.5 crate. Its only runtime-code
change is the two-line `VariantStrIter::impl_get` fix from upstream commit
`b5a4071e439bef2b5eea76c3aa25e5ae84839e34`:

- make the C output-pointer variable mutable;
- pass `&mut p`, not `&p`, to `g_variant_get_child`.

The GTK3/Tauri dependency graph requires the 0.18 API. This backport does not
rename the crate to 0.20, suppress advisory IDs or migrate the desktop stack.
The original archive SHA-256 is
`233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.
`UPSTREAM-FILES.json` records all 121 original files and their identities.
The source-integrity regression rejects changes beyond that fix and the exact
crate-local compiler-lint compatibility settings described below.
Only this note and the inventory are additional files; LICENSE and COPYRIGHT
are unchanged. The workspace patch selects this source for the Linux wallet.

The normalized Cargo manifest additionally allows the stylistic
`mismatched_lifetime_syntaxes` lint in this crate only. Rust 1.94.1 crashed in
its diagnostic renderer while displaying this lint at the default output width;
an explicit diagnostic width of 200 avoided that compiler crash and allowed the
runtime regression to pass. The crate-local setting makes the fix build without
special caller flags. `unknown_lints` is allowed for Rust 1.88, which predates
that lint. No security advisory, runtime test, workspace lint or other crate is
suppressed; other original warnings remain visible.

References:

- https://rustsec.org/advisories/RUSTSEC-2024-0429.html
- https://github.com/gtk-rs/gtk-rs-core/pull/1343
- https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34

Run `tools/linux-wallet-dependency-check` in an optimized Linux build. The
corresponding unpatched 0.18.5 reproducer failed with SIGSEGV under
Rust 1.94.1. A source inventory check alone does not replace the runtime test.
