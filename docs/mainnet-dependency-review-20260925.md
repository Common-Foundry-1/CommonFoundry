# Mainnet dependency review - September 25, 2026

This is a source/dependency review and focused internal regression evidence.
It is not an external audit, a guarantee against unknown vulnerabilities, or
approval of final binaries. No running service or published site was changed.

## Explorer build tooling

The explorer's pinned Wrangler 4.127.1 brought in a `sharp` version affected by
[GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c), concerning
libheif image decoding. npm reported three high-severity entries along the one
`wrangler -> miniflare -> sharp` dependency chain. The production-only npm audit
was already clear; this finding concerned development/build tooling, not proof
that the deployed explorer processed vulnerable image inputs.

Wrangler is now pinned to 4.141.0, whose declared Miniflare dependency is
5.20260925.0-alpha and whose `sharp` dependency is the patched 0.35.4. The
lockfile and SDK-generated Worker types were updated together. No dependency
override or audit-ignore rule was added.

Validation completed:

- fresh locked install with lifecycle scripts disabled;
- zero npm findings in the updated explorer dependency graph;
- generated Worker types checked current, both TypeScript checks passed;
- all 74 explorer tests passed;
- mainnet frontend build and unrouted Worker deployment **dry run** passed.

Wallet, public pool dashboard and operator-dashboard npm audits each reported
zero findings as well. The explorer CI job now enforces its npm audit, in
addition to existing build/type/test checks. No actual Worker was deployed.

## Linux wallet GLib correction

The GTK3/Tauri dependency graph selects GLib 0.18.5, affected by
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html).
An optimized Rust 1.94.1 test using only synthetic strings reproduced SIGSEGV
in its string-variant iterator. A controlled repeat used identical regression
source and locked dependency versions; it also failed with the unpatched crate.

The local patch preserves the 0.18 API/version and backports the upstream
[two-line output-pointer fix](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34).
The exact published archive was authenticated first. Its 121-file inventory,
licenses and provenance are retained under
`third_party/glib-0.18.5-variant-str-iter`.

The only runtime source change is a mutable output-pointer variable/reference.
The Cargo manifest also contains a narrowly scoped compiler-style-lint
compatibility setting: Rust 1.94.1 crashed while rendering
`mismatched_lifetime_syntaxes` on this old library. A diagnostic-width change
confirmed the renderer issue; the documented crate-local setting permits normal
builds without requiring special caller flags. It does not suppress workspace
warnings, security advisories or runtime tests. Three original `unused_parens`
warnings remain visible.

The patched optimized regression passed both iterator/Unicode/empty-array
tests with ordinary compiler settings. Strict Clippy passed for the regression
project; source-integrity tests allow only the reviewed runtime and build
changes. CI runs that optimized regression plus the inventory check. The
standalone test uses the same patched library selected by the Linux wallet;
full native-wallet and final-package checks remain separate.

The node and miner's mainnet dependency graphs do not select GLib. No consensus,
proof, wire encoding, wallet encryption, economic parameter or launch schedule
was changed by these corrections. No actual wallet, key or chain was opened
by the synthetic regression.

## Remaining Rust maintenance warnings

Cargo-audit 0.22.2 checked 765 lockfile dependencies against RustSec database
commit `e2111519ba6d14a5da59a7b2e5c8083ae8a37c01`, updated September 25.
It reported zero vulnerability entries and nine unmaintained-package warnings,
with an empty advisory-ignore list. Its registry scan does not validate the
local GLib patch: the exact-source and runtime regression above provide that
mitigation evidence.

| Dependency | Actual path/scope | Disposition |
|---|---|---|
| ansi_term 0.12.1 | tracing-forest through pinned SP1/slop utilities | Retained logging dependency; track upstream maintenance/replacement. |
| bincode 1.3.3 | cmfd-consensus and dory-pcs | Retain the pinned encoding implementation; any migration needs explicit compatibility and proof/serialization testing. |
| paste 1.0.15 | Compile-time macro used by arkworks/Plonky3 | Retain the pinned source; evaluate a maintained replacement with upstream proof-library updates. |
| proc-macro-error 1.0.4 | Compile-time GTK/GLib macro dependencies | Track GTK3/Tauri dependency maintenance; not a newly discovered runtime vulnerability. |
| Five unic 0.9.0 crates | urlpattern through tauri-utils, including runtime and build paths | Retain pinned versions with maintenance follow-up; these were not represented as build-only dependencies. |

These are outstanding maintenance items, not suppressed findings or claims that
unmaintained code is risk-free. Advisory status is time-sensitive and must be
checked again for the final frozen release. Final signed-package qualification,
current-worker GPU checks and owner approval remain required.
