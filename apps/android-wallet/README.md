# Common Foundry Android Wallet

This is the mainnet Android wallet source. It is a Rust wallet core with a Tauri/React interface and an Android Keystore storage bridge. The app supports English and French and uses the official Common Foundry mark and mineral/graphite/copper design tokens.

## Security boundary

Keys are generated, restored, and used to sign in Rust. The local encrypted wallet is wrapped by Android Keystore; a portable encrypted backup is required before a new wallet is activated. The app does not send private keys or passphrases to either public service.

`wallet.commonfoundry.ai` proposes UTXOs and broadcasts signed transactions. Before a payment is prepared and again before signing, the app compares every selected input with its confirmed transaction output **and** a separately validating proof node. The explorer Worker pins the primary path to Germany's own mainnet node and a backup path to the local Proxmox CMFD-Relay node. The app uses Proxmox only if Germany is unreachable or more than six blocks behind the wallet snapshot. A valid missing or unavailable input, wrong-network answer, malformed response, stale backup, or conflicting value blocks sending. The Send screen stays disabled until at least one identified proof route is available.

This is independent node corroboration, not full chain validation on the phone. Both services or their shared control plane could still be compromised. See [the deployment and threat-model notes](../../docs/android-wallet-independent-utxo.md).

## Source checks

```sh
cargo test --locked
cargo test --locked -p cmfd-wallet-api -- --ignored
cargo clippy --locked --all-targets -- -D warnings
cd app
pnpm install --frozen-lockfile
pnpm check
pnpm test
pnpm build
cd src-tauri
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

The two Cargo workspaces have separate lockfiles. Run the core workspace checks from this directory and the Tauri checks from `app/src-tauri`.

## Android build

Use JDK 17, Android Platform/Build Tools 36, NDK r30, and the Rust `aarch64-linux-android` target. From `app`, run:

```sh
pnpm tauri android build --apk --target aarch64
```

The generated Android project includes a SHA-256-pinned Gradle 8.14.3 distribution and an official wrapper JAR checked against Gradle's published hash. On Windows hosts that prohibit symlink creation, Tauri may finish the optimized Rust library then fail while linking it into `jniLibs`; copy that exact library into `app/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/` and run Gradle's `:app:assembleUniversalRelease` with the Rust task excluded. Verify the library hash in the APK matches the compiled library.

No signing key belongs in this repository. An unsigned build is for static inspection only. Public distribution requires an independently reviewed source commit, a tested ARM64 device build, protected official signing, APK/source verification, and authenticated checksums. No production node, tunnel, Worker, or key operation is authorized by this README.

The `Android wallet unsigned build` workflow checks both Rust lockfiles and the UI dependencies, runs the core and UI tests, and retains the unsigned ARM64 APK with its SHA-256 checksum for seven days. The CI artifact is a review input, not an official signed release.
