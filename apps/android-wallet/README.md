# Common Foundry Android Wallet

This is the mainnet Android wallet source. It is a Rust wallet core with a Tauri/React interface and an Android Keystore storage bridge. The app supports English and French and uses the official Common Foundry mark and mineral/graphite/copper design tokens.

## Acknowledgments

Thanks to **Qcvibes1** for contributing the original Android Wallet V1 package that started this work. The current release includes subsequent Common Foundry integration, security changes, and review.

## Security boundary

Keys are generated, restored, and used to sign in Rust. The local encrypted wallet is wrapped by Android Keystore; a portable encrypted backup is required before a new wallet is activated. The app does not send private keys or passphrases to either public service.

`wallet.commonfoundry.ai` proposes UTXOs and broadcasts signed transactions. Before a payment is prepared and again before signing, the app compares every selected input with its confirmed transaction output **and** a separately validating proof node. The explorer Worker pins the primary path to Germany's own mainnet node and a backup path to the local Proxmox CMFD-Relay node. The app uses Proxmox only if Germany is unreachable, returns a retryable service error, or is more than six blocks behind the wallet snapshot. A valid missing or unavailable input, wrong-network answer, malformed response, stale backup, or conflicting value blocks sending. The Send screen stays disabled until at least one identified proof route is available.

This is independent node corroboration, not full chain validation on the phone. Both proof transports currently pass through the Germany tunnel host, so that host's failure blocks sending. Both services or their shared control plane could still be compromised. See [the deployment and threat-model notes](../../docs/android-wallet-independent-utxo.md).

The QR scanner uses Google ML Kit. Google says camera input and scan results remain on the device, but ML Kit may send usage and performance metrics. The app discloses this beside Scan and links its offline Android, Rust, and JavaScript license notices from Settings. See [third-party notices](THIRD_PARTY_NOTICES.md).

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

The adaptive launcher foreground is generated from `app/src-tauri/icons/icon.png` by `scripts/generate-android-launcher-icons.ps1` on Windows. It centers the original copper CF mark within Android's 66 dp safe circle, leaving extra room for device-specific icon masks. Re-run it after regenerating the Android project resources.

No signing key belongs in this repository. An unsigned build is for static inspection only. Public distribution requires a security-reviewed source commit, a tested ARM64 device build, protected official signing, APK/source verification, and authenticated checksums. No production node, tunnel, Worker, or key operation is authorized by this README.

The `Android wallet unsigned build` workflow checks both Rust lockfiles and the UI dependencies, runs the core and UI tests, regenerates the bundled license notices, and checks their presence in the unsigned ARM64 APK. It retains that APK with its SHA-256 checksum for seven days. The CI artifact is a review input, not an official signed release.
