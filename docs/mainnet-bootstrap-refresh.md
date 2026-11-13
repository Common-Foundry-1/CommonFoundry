# Mainnet bootstrap refresh

The signed height 58,424 bootstrap is an optional trusted, pruned starting
point. Its installer preserves a wallet key and settings and then lets the
normal node validate newer blocks. It is not independent historical proof or
an archive-node replacement.

## Decide when to refresh

Compare the published `BOOTSTRAP.json` with a healthy, independently checked
mainnet node's accepted height. The default operational review threshold is
7,200 blocks (five days at the 60-second target); adjust it for the support
and hosting budget. A pre-fork snapshot also needs a new compatible release
after compact activation, regardless of its age.

```sh
python3 scripts/mainnet_bootstrap_freshness.py \
  --manifest /path/to/published/BOOTSTRAP.json \
  --tip-height 59340
```

The checker reads a local manifest and a supplied height. It does not verify
the release signature or the node's identity. Obtain those separately; do not
use its output as evidence that a snapshot is safe to install.

## Prepare a replacement

1. Confirm that two independent full nodes agree on the canonical tip,
   validated work height, network ID and consensus fingerprint. Inspect their
   storage health and pruning state. Choose a snapshot height at least 100
   blocks below both tips.
2. Capture from a stopped isolated copy of a healthy node. Freeze exact log,
   startup state, index, work-status and prune-anchor bytes. Exclude wallet
   keys, credentials, peer lists and logs. Keep the original live node running
   and unchanged.
3. Build a new, height-specific release tag and manifest. Recheck every
   capture hash, archive member, network identity and fingerprint. The previous
   height 58,424 packaging scripts in the local operator workspace contain
   release-specific pins; use new copies with the new values, never overwrite
   the published release or its qualification evidence.
4. Test the exact archived parts and installers on disposable initialized
   wallets on Windows and Linux. Check preserved keys and settings, rollback
   after interruption, healthy storage, normal work validation and P2P
   catch-up to an independently observed public tip. Test with the current
   stable runtime and the fork-aware runtime when applicable.
5. Sign the checksum manifest with the existing owner release key, verify the
   signature and a tampered-manifest rejection, then publish the frozen assets
   as an optional bootstrap release without changing the stable wallet
   `latest` pointer. Preserve the qualification receipts and the explicit
   trusted-checkpoint disclosure.

The current installer pins its release tag, manifest hash and consensus
fingerprint. A new capture requires newly qualified installers; updating a
manifest alone cannot make the existing installer follow the fork.
