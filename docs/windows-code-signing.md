# Windows wallet code signing

The mainnet `SHA256SUMS.txt.sig` signature authenticates release archives to the
wallet updater. It is not a Windows Authenticode signature on the executables.
Windows Smart App Control can block an unsigned staged wallet at launch even
after the updater verifies the archive. The v1.0.20 Windows executables were
published without Authenticode signatures; the reported Event ID 3077 and OS
error 4551 are consistent with that failure. Do not ask users to turn off
Smart App Control.

Before assembling another Windows release:

1. Build and compare the native executables from the frozen source as usual.
2. Use a trusted code-signing provider to Authenticode-sign `cmfd-launch.exe`,
   `cmfd-node.exe`, `common-foundry-wallet.exe`, and `cmfd-miner.exe`. Timestamp
   the signatures. Keep signing credentials outside the source tree and release
   artifacts. The release checksum SSH key cannot serve as a Windows code-signing
   certificate.
3. Supply those signed executables to both Windows package assemblies. The
   package script now rejects any executable whose Windows Authenticode status
   is not `Valid`, whose signer lacks the Code Signing certificate usage, or
   whose signature has no timestamp certificate.
   Preserve the independent comparison of the original unsigned builds and
   record that the two archives used the same signed executable inputs.
4. Complete package, checksum, and release signing only after code signing,
   because Authenticode changes executable bytes and thus package hashes.
5. Test the exact signed archive through the updater on a Windows 11 machine
   with Smart App Control enforcing. A locally valid Authenticode status is
   necessary for this gate but does not by itself prove acceptance on every
   device or under an organization-specific App Control policy.

The published v1.0.20 archive cannot be repaired by re-signing its extracted
files: that would invalidate its signed manifest. Ship a new version with
signed Windows executables and new release checksums. A machine that cannot
launch its older unsigned wallet also needs a trusted distribution path for
the replacement; the updater cannot override Windows App Control.
