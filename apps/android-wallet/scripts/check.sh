#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$project_dir"
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

if [[ "${CMFD_LOOPBACK_TESTS:-0}" == "1" ]]; then
  cargo test -p cmfd-wallet-api -- --ignored
fi

cd "$project_dir/app"
pnpm check
pnpm test
pnpm build

cd "$project_dir/app/src-tauri"
cargo check
