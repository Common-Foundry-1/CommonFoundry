# Mainnet plan approvals

The existing ProductionV4 qualification gate remains required. RC approval does
not authorize mainnet. The mainnet plan needs an additional exact-byte approval
that binds the reviewed source, the canonical plan, the qualified model/proof
material and the committed signer/verifier policy.

`scripts/mainnet_plan_approval.py` does not select reviewers, generate signing
keys, sign requests, change release pins or activate a network. `prepare` creates
unsigned requests; `verify` checks both externally supplied signatures and writes
a canonical manifest. Distinct keys are necessary but do not, by themselves,
prove organizational independence or the quality of a review.

## Prerequisites

- Final reward receiving addresses and starting target, with custody/recovery
  evidence. Generate the canonical plan with the Rust mainnet-plan command.
- Validated ProductionV4 qualification evidence and its canonical pin-phase
  approval subject. This tool checks its binding and artifact agreement; it does
  not replace the full proof-qualification verifier.
- A named producer and independent reproducer, each with a separate dedicated
  allowed-signers policy and control of their own private signing key.
- A canonical, committed trust JSON object containing `producer`,
  `independent_reproducer` and `ssh_keygen_sha256`. Each role contains
  `signer_identity`, `allowed_signers_sha256`, `key_blob_sha256`, `key_fingerprint`
  and `key_type`. Derive these from the actual public allowed-signers files and
  the trusted OpenSSH executable; never fill in guessed hashes or fixture values.
  For final release tooling, commit it at `packaging/mainnet/APPROVAL-TRUST.json`
  before freezing the review commit.
- A clean, exact review checkout with final versions and code. Both qualifying
  source history and trust policy must belong to that checkout.

The dedicated ProductionV4 activation SSH namespaces are retained for these
same authorities. Mainnet uses distinct subject and role-payload schemas, so an
RC signature or a signature for the other role cannot approve a mainnet request.
Do not broaden the allowed-signers namespace restriction.

## Workflow

1. Run `prepare` with absolute paths for `--repo`, `--plan`,
   `--qualification-subject`, `--trust`, `--producer-policy`,
   `--reproducer-policy`, and a new `--output` directory outside tracked source.
   Supply `--review-commit`, `--producer-identity` and `--reproducer-identity`.
2. Each actual reviewer inspects SUBJECT.json and their role request, verifies
   the referenced evidence, and signs their own exact request using the
   namespace in that request. Keep private keys with their owners. The tool
   cannot provide or infer an independent reviewer.
3. Run `verify` with the same inputs plus `--producer-approval`,
   `--producer-signature`, `--reproducer-approval`, `--reproducer-signature`,
   `--ssh-keygen` and `--ssh-keygen-sha256`. The executable digest must match the
   precommitted trust policy. Use a new output file for MAINNET-APPROVALS.json.
4. Preserve both signed requests, signatures, public policies, qualification
   subject and trust document with the review evidence. The manifest hashes
   those records; it is not a substitute for retaining or publishing them.
5. After all qualification/review requirements are satisfied, the mainnet pin
   configuration must include the verified manifest digest and matching proof
   trust. Generate candidates with `scripts/generate_mainnet_pins.py` as described
   below. Application and final release signing remain separate operations.
6. Assemble with `--approval-manifest` and run the four-package preflight. The
   packaged manifest must match the compiled digest, plan and proof authority
   descriptors. Only the two explicit mainnet pin files may change after the
   reviewed commit. Any code, dependency, version or other source change needs
   a new reviewed commit and new signed requests.

No future beacon signature is included in an approval request. The pinned
October schedule and genesis policy are approved, while the live beacon is
verified separately at activation. Passing signature checks is not proof that
deployment, recovery, mining/payouts or the final launch rehearsal are complete.

## Generate the two pin candidates

Supply the same clean review checkout, canonical plan, qualification subject,
trust document, both role policies/requests/signatures and pinned SSH verifier.
Also provide `--proof-pin` (the canonical dual-party ProductionV4 review target)
and `--approval-manifest` (the verified MAINNET-APPROVALS.json). Use a new absolute
`--output` directory outside the source repository.

The proof target must come from the existing qualified proof workflow and must
match the source-pin digest in the signed qualification subject. Do not reset
or overwrite the active RC proof pin to prepare mainnet. RC single-producer
targets cannot be used here. All actual qualification and reviewer evidence
remains required; syntactically valid hashes are not such evidence.

The generator re-verifies both mainnet signatures. It accepts only the existing
canonical literal format, never evaluates arbitrary Rust, and checks the report,
specification and authority bindings. It emits mainnet_release_pin.inc.rs,
mainnet_network_id.inc.rs and PIN-REVIEW.json. It neither applies them nor starts
a node. Existing output directories are not overwritten; failure cleanup removes
only files created by this invocation and preserves any concurrent operator file.

After independently reviewing the candidate hashes and contents, apply only the
two generated includes in the intended source locations, commit them, build the
mainnet-feature binaries, and run the native identity/packaging checks. Full
mainnet plan parsing and the signed-package rehearsal are still required. A Rust
syntax/type smoke test of a generated include is not a release authorization.

## Final binary reproduction and release gate

After both native package sets have been independently built, prepare a release
stage with the four archives and these exact public evidence filenames:

- MAINNET-PLAN.json, MAINNET-APPROVALS.json
- MAINNET-QUALIFICATION-SUBJECT.json, MAINNET-APPROVAL-TRUST.json
- PRODUCTION-V4-REVIEWED-PIN.review
- DASHBOARD-ASSETS.json (the exact reviewed dashboard manifest used for all four packages)
- CUDA-RUNTIME-SHA256.txt (the exact reviewed Linux x86-64 `libcudart.so.12` SHA-256, lowercase hex plus newline)
- MAINNET-PLAN-PRODUCER-APPROVAL.json and its .sig
- MAINNET-PLAN-REPRODUCER-APPROVAL.json and its .sig
- MAINNET-PRODUCER.allowed_signers, MAINNET-REPRODUCER.allowed_signers

Prepare the dashboard manifest from the exact clean frozen commit with
`scripts/prepare_mainnet_dashboard.py`; see
[`mainnet-dashboard-assets.md`](mainnet-dashboard-assets.md). Its build record
is first-person toolchain evidence, not a substitute for independent package
reproduction or a release approval.

Use `scripts/mainnet_release.py` with `--repo`, `--commit`, `--version`,
`--producer-stage`, `--reproducer-stage`, `--ssh-keygen`,
`--ssh-keygen-sha256` and a new `--output` file. Both stages are fully inspected;
the same directory or hardlinked archives cannot stand in for two builds.
The output is an unsigned first-person reproduction statement. Matching bytes
alone do not establish independence. Only the actual independent reproducer
should sign it after genuinely rebuilding and checking those packages.

Stage the exact statement as MAINNET-REPRODUCTION.json and its detached signature
as MAINNET-REPRODUCTION.json.sig. Its signature uses the already committed
independent-reproducer authority and namespace. A producer signature cannot
replace it. Include every staged artifact/evidence filename in the release
inventory, committed before the review freeze.

The normal `release_integrity.py finalize` and `verify` commands now dispatch
mainnet artifacts through this gate, including plain version labels such as
1.0.0. Supply the pinned `--activation-ssh-keygen` and
`--activation-ssh-keygen-sha256`. The gate rechecks plan signatures, exact applied
pins, four-package consistency, public evidence and the reproduction statement.
The ordinary finalizer then produces BUILDINFO, source SBOM, provenance and
checksums. It does not sign those checksums or publish anything. The normal
offline release-signing/download-verification step remains required, together
with the deployment and launch rehearsal.
