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
   trust. Pin generation/application and final release signing are separate
   operations; this tool does not perform them.
6. Assemble with `--approval-manifest` and run the four-package preflight. The
   packaged manifest must match the compiled digest, plan and proof authority
   descriptors. Only the two explicit mainnet pin files may change after the
   reviewed commit. Any code, dependency, version or other source change needs
   a new reviewed commit and new signed requests.

No future beacon signature is included in an approval request. The pinned
October schedule and genesis policy are approved, while the live beacon is
verified separately at activation. Passing signature checks is not proof that
deployment, recovery, mining/payouts or the final launch rehearsal are complete.
