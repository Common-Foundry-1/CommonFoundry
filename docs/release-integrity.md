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
`packaging/releases/v0.1.0-devnet.14.inventory`. `BUILDINFO.json`,
`SOURCE-SBOM.json`, `PROVENANCE.intoto.jsonl`, and `SHA256SUMS.txt` are generated
and therefore are intentionally absent from that inventory:

```text
python scripts/release_integrity.py finalize --repo . --expected-commit <commit> --version 0.1.0-devnet.14 --stage <asset-directory> --inventory packaging/releases/v0.1.0-devnet.14.inventory
python scripts/release_integrity.py verify --repo . --expected-commit <commit> --version 0.1.0-devnet.14 --stage <asset-directory> --inventory packaging/releases/v0.1.0-devnet.14.inventory
```

These commands neither upload nor publish anything. Final download
authentication still requires the independently verified final checksum file
to be signed and associated with the signed release tag. Before signing, build
the release on two independent machines and require a byte-for-byte match:

```text
python scripts/release_integrity.py compare \
  --repo . --expected-commit <commit> --version <version> \
  --first-stage <first-asset-directory> \
  --second-stage <second-asset-directory> \
  --inventory <tracked-inventory>
```

Both directories are fully reverified against the same clean source commit and
tracked inventory before every file is stream-compared with bounded memory. A
difference in generated metadata, file inventory, file size, or file content
fails the comparison and identifies the differing class or file.

`SOURCE-SBOM.json` is a canonical inventory of every package pinned by the
tracked Cargo and wallet/pool npm lockfiles. It records source-lock scope
explicitly: it is not a claim that every locked development dependency is
reachable from every shipped binary. `PROVENANCE.intoto.jsonl` is an in-toto
Statement binding the staged artifacts to the exact Git commit and tree,
tracked inventory, source SBOM, source epoch, and finalizer identity. Its custom
predicate records release assembly; it does not claim a SLSA build level or
replace authenticated provenance emitted by an independent build platform.

After that gate passes, keep the private
Ed25519 release key offline and outside every checkout. Sign the exact generated
checksum file with the fixed namespace:

```text
ssh-keygen -Y sign -f <offline-release-key> -n commonfoundry-release SHA256SUMS.txt
```

Place the resulting `SHA256SUMS.txt.sig` beside the staged checksum file. The
trusted signer policy is an externally distributed OpenSSH allowed-signers file
containing the expected public key and identity. Verify the complete release,
including the exact inventory and signature, before publication:

```text
python scripts/release_integrity.py verify-signed \
  --repo . --expected-commit <commit> --version <version> \
  --stage <asset-directory> --inventory <tracked-inventory> \
  --allowed-signers <trusted-allowed-signers> \
  --signer-identity <release-identity> \
  --ssh-keygen <trusted-ssh-keygen-path>
```

The command rejects a missing or extra signature, malformed signer identity,
untrusted key, wrong namespace, modified checksum, modified asset, or changed
source identity. Build receipts still do not replace an independent
reproducible-build comparison.

Operators and update tooling can authenticate the downloaded directory without
access to the private source checkout:

```text
python scripts/release_integrity.py verify-download \
  --stage <downloaded-release-directory> \
  --allowed-signers <trusted-allowed-signers> \
  --signer-identity <release-identity> \
  --ssh-keygen <trusted-ssh-keygen-path>
```

This verifies the detached signature before trusting the checksum manifest,
requires the exact signed flat-file inventory, streams and hashes every file,
and cross-checks the build identity, source SBOM, and release-assembly
provenance. It is the authentication boundary used by update and rollback
qualification; the private repository is not distributed to clients.

Planned and emergency signer changes follow
[`production-key-operations.md`](production-key-operations.md). The
`scripts/release-key-transition.py` harness creates a canonical transition
record and verifies distinct old-key and new-key signatures under the dedicated
`commonfoundry-release-key-transition` namespace before a successor policy is
distributed.
