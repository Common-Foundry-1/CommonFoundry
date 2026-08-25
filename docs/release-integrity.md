# Release identity guards

The release scripts use explicit commit checks, native build receipts, canonical
archives, a tracked asset inventory, and final SHA-256 metadata to catch stale
or mixed build inputs. These are identity and consistency guards. A native
build receipt is self-recorded metadata; it does not authenticate the compiler,
prove that the recorded command ran, or establish who built the library.

The release commit must be supplied from the intended candidate or signed tag.
The build and package scripts never select a release commit from the checkout's
current `HEAD`. Windows scripts require `-ExpectedCommit`; Linux builders accept
the commit as their second argument, the package script accepts it as its fourth
argument, and all three accept `CMFD_RELEASE_COMMIT`.

Windows examples:

```powershell
$releaseCommit = '<full-lowercase-release-commit>'
.\scripts\build-cuda-miner.ps1 -ExpectedCommit $releaseCommit
.\scripts\build-opencl-miner.ps1 -ExpectedCommit $releaseCommit
.\scripts\package-standalone-miner.ps1 -ExpectedCommit $releaseCommit
```

Linux examples on an x86-64 glibc host whose Rust host is
`x86_64-unknown-linux-gnu`:

```bash
export CMFD_RELEASE_COMMIT='<full-lowercase-release-commit>'
bash scripts/build-cuda-miner.sh
bash scripts/build-opencl-miner.sh
bash scripts/package-standalone-miner.sh
bash scripts/prepare-tauri-appimage-tools.sh "$CMFD_RELEASE_COMMIT" prepare
(cd apps/wallet && npm run desktop:build -- --ci -- --locked)
bash scripts/prepare-tauri-appimage-tools.sh "$CMFD_RELEASE_COMMIT" verify
bash scripts/normalize-linux-appimage.sh \
  "target/release/bundle/appimage/Common Foundry Wallet_0.1.0-devnet.14_amd64.AppImage" \
  "$CMFD_RELEASE_COMMIT" \
  "0.1.0-devnet.14"
bash scripts/normalize-linux-deb.sh \
  "target/release/bundle/deb/Common Foundry Wallet_0.1.0-devnet.14_amd64.deb" \
  "$CMFD_RELEASE_COMMIT" \
  "0.1.0-devnet.14"
```

Each native builder creates a `.build-receipt` beside its library from the same
invocation that built and inspected the binary. Packaging rejects a missing,
changed, wrong-commit, wrong-source, wrong-script, wrong-target, or stale
receipt. The Linux path also checks the host, glibc Rust target, and ELF class,
machine, and type. The Linux CUDA builder strips nonessential symbols before
inspection and records the strip tool version in the receipt. This removes
nvcc process-specific temporary symbols from the shipped library while keeping
the required CUDA images and PTX fallback intact.

The Linux `.deb` normalizer rejects links and special files, fixes all package
timestamps to the release commit's `SOURCE_DATE_EPOCH`, rebuilds with root
ownership and uniform gzip compression, validates the package, and requires a
byte-identical second normalization pass before atomically replacing the Tauri
output. It requires an Ubuntu 22.04-compatible GNU userland with `dpkg-deb`
support for root ownership and uniform compression, and prints the semantic
package hash plus exact packaging-tool versions in the build log.

Before Tauri runs, the release workflow downloads or reuses all five AppImage
helpers only when they match their pinned SHA-256 digests. The GTK and
GStreamer scripts use immutable commit URLs; mutable release assets are
accepted only when their bytes match the recorded digest. The tools are checked
again after Tauri exits so a build-time replacement cannot pass unnoticed.

The Linux AppImage normalizer extracts the Tauri-built image without mounting
it, rejects escaping links, hard links, and special files, removes group/world
write and set-id permission, and makes the wrapper and application entrypoints
executable by ordinary users. It fixes payload timestamps to
`SOURCE_DATE_EPOCH`, compares the complete content, mode, and symlink inventory
before and after repacking, runs both the extracted entrypoints and outer image
as an unprivileged user, and requires a byte-identical second repack before
atomically replacing the Tauri output. CI uploads only the final AppImage and
`.deb`; raw AppDir and Debian staging trees are not release artifacts.

The final flat asset directory is constrained by the tracked
`packaging/releases/v0.1.0-devnet.14.inventory`. `BUILDINFO.json` and
`SHA256SUMS.txt` are generated and therefore are intentionally absent from that
inventory:

```text
python scripts/release_integrity.py finalize --repo . --expected-commit <commit> --version 0.1.0-devnet.14 --stage <asset-directory> --inventory packaging/releases/v0.1.0-devnet.14.inventory
python scripts/release_integrity.py verify --repo . --expected-commit <commit> --version 0.1.0-devnet.14 --stage <asset-directory> --inventory packaging/releases/v0.1.0-devnet.14.inventory
```

These commands neither upload nor publish anything. Final download
authentication still requires the independently verified final checksum file
to be signed and associated with the signed release tag. The build receipts do
not replace that signature or an independent reproducible-build comparison.
