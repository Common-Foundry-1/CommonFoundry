# Separate mainnet starting and easiest targets

The mainnet launch-plan schema is now `CMFD_MAINNET_LAUNCH_PLAN_V2`. V1 documents
are rejected rather than silently assigning a minimum or starting difficulty.
The plan payload includes an explicit `initial_target`; the existing
`rules.proof_of_work.pow_limit` remains the easiest permissible target.

Both must be nonzero 256-bit lowercase hexadecimal values. The initial target
must be no greater than the limit. Smaller targets mean harder work.

The owner-selected candidate is:

- Initial: `000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb` (5x RC).
- Limit: `003fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` (RC minimum).

This work carries the initial target through the canonical plan, plan/network
identity derivation, generated release configuration, compiled profile, native
prelaunch comparison and runtime consensus fingerprint. A changed initial
target requires a changed signed plan, network identity and release pin. Missing,
zero, too-easy and mismatched targets are rejected by native and package checks.
Existing RC/development profiles retain `initial_target: None` and their original
fingerprints; their targets and adjustment algorithm were not changed.

The digest domains are `CMFD/MAINNET/LAUNCH-PLAN/V2` plus a trailing zero byte for
SHA-256 over the compact payload, and `CMFD/MAINNET/NETWORK-ID/V2` for the existing
BLAKE3 derivation. The launch-time beacon still authenticates that exact digest.

The CLI requires both `--pow-limit` and `--initial-target` for `mainnet-plan`.
Supply the two real reward destinations separately; no recipient is selected
automatically. Plan generation is not activation or approval. Actual source pin
files remain `None`; synthetic fixture keys and test signatures never authorize
a live release.

The updated target integration does not activate the separately evaluated ASERT
candidate. Current consensus still uses the existing DGW-style adjustment.
Controlled dropout recovery and final package rehearsal remain outstanding.

The owner explicitly declined requests for an external cryptographer. Reports
must label this work as internal validation and must not claim a third-party
cryptographic audit. No test-only signer may be passed off as an independent
reviewer or release authority.
