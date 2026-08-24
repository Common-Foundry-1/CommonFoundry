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
```

Each native builder creates a `.build-receipt` beside its library from the same
invocation that built and inspected the binary. Packaging rejects a missing,
changed, wrong-commit, wrong-source, wrong-script, wrong-target, or stale
receipt. The Linux path also checks the host, glibc Rust target, and ELF class,
machine, and type.

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
