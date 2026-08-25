# Windows Production V3 qualification harness

This procedure runs one unchanged production-size Dory V3 qualification on a
Windows host. It is deliberately separate from Devnet mining and from the
production release switch. A successful run creates a cryptographically bound
evidence **candidate**; it does not enable RCNet-1, change a consensus selector,
or make a build releasable as RC1.

## Preconditions

- Use 64-bit Windows, PowerShell 7, Python 3, Git, and the Rust toolchain.
- Check out the exact source commit to qualify. The worktree must be completely
  clean for the whole run.
- Keep the model bank, canonical Record V2, and strict qualification request at
  existing absolute paths outside the source tree.
- Generate the request with the feature-gated `dory-v3-qualify-request`
  command from this same source commit. The harness treats that request as an
  immutable input and binds its exact SHA-256.
- Supply a new output directory and a new scratch directory. Neither may
  exist. They must not overlap, and both must be outside the source tree.
- The scratch argument must be an explicit absolute `D:\...` path with an
  existing, ordinary parent directory. Junctions, symlinks, and other reparse
  points are rejected.

The producer's current code floor is `53,687,091,200` free bytes. The harness
adds a default `17,179,869,184`-byte operator margin, so it requires at least
`70,866,960,384` free bytes on the D: volume before it starts and checks again
immediately before proving. This is a free-space gate, not an estimate of final
use. The Rust producer independently repeats its own resource and memory
preflights.

If the strict request has not been created yet, use the same clean commit and
feature gates to create it at an absent path. The seed must contain only the
complete block challenge and selected nonce; it cannot supply either computed
digest:

```powershell
$env:CARGO_TARGET_DIR = 'D:\cmfd-request-build-001'
cargo build --release --locked -p cmfd-consensus `
  --features dory-bls12-381-prototype,whir-prototype

& 'D:\cmfd-request-build-001\release\cmfd-consensus.exe' `
  dory-v3-qualify-request `
  --bank D:\cmfd-model\MODEL-V2.bank `
  --record D:\cmfd-model\DORY-V3-MODEL-RECORD-V2.json `
  --seed D:\cmfd-model\qualification-seed.json `
  --scratch D:\cmfd-request-scratch\run-001 `
  --request-output D:\cmfd-model\qualification-request.json
```

The request scratch and request output must also be absent. A request output is
complete only when this command exits successfully. It is an input to the
qualification harness, not activation evidence by itself.

## Run

Resolve and record the complete commit first:

```powershell
$commit = (git -C C:\Source\CommonFoundry rev-parse HEAD).Trim()
```

Then run the harness with the real artifacts and new destinations:

```powershell
C:\Source\CommonFoundry\scripts\run-production-v3-qualification.ps1 `
  -ExpectedCommit $commit `
  -Bank D:\cmfd-model\MODEL-V2.bank `
  -Record D:\cmfd-model\DORY-V3-MODEL-RECORD-V2.json `
  -Request D:\cmfd-model\qualification-request.json `
  -OutputDirectory D:\cmfd-qualification\run-001 `
  -ScratchDirectory D:\cmfd-qualification-scratch\run-001 `
  -MaximumNativeBlockRows 131072
```

The harness builds a new `cmfd-consensus.exe` from the named clean commit with
exactly these feature gates:

```text
dory-bls12-381-prototype,whir-prototype
```

It then executes `dory-v3-qualify`. Only a zero exit status plus the producer's
create-new report allows the workflow to continue. The JSONL journal is always
treated as diagnostic-only, non-resumable state; even a 16-record journal is
never interpreted as completion.

After the producer exits, the harness starts
`dory-v3-verify-qualification` as a new operating-system process. The fresh
verifier rereads and authenticates all persisted inputs, the report, the exact
journal, and the proof. The producer and verifier process IDs must differ.

## Interruption and retry

Pressing Ctrl+C asks the active child process to cancel and gives it 120 seconds
to exit cleanly before the harness terminates it. An interrupted or failed run
never emits an activation-evidence candidate. A retained journal describes
progress only. It is not a checkpoint and must not be resumed.

Keep a failed output directory for diagnosis or quarantine it. Start any retry
with different, absent output and scratch paths. The harness never overwrites
an artifact or log from an earlier attempt.

## Successful outputs

The new output directory contains:

| File | Meaning |
| --- | --- |
| `qualification-proof.cmfd` | Canonical persisted Production V3 proof wire. |
| `producer-report.json` | Producer completion marker and exact measurements. |
| `producer-journal.jsonl` | Diagnostic-only, non-resumable progress journal. |
| `PRODUCTION-V3-INDEPENDENT-VERIFIER-REPORT.json` | Report from the separate verifier process. |
| `PRODUCTION-V3-INDEPENDENT-VERIFIER.bin` | Create-new exact copy of the verifier executable used. |
| `producer-stdout.json` | Exact producer stdout; it must byte-match the producer report. |
| `fresh-verifier-stdout.json` | Exact verifier stdout; it must byte-match the verifier report. |
| `*-stderr.log` and `build-*.log` | Exact process output retained and hashed. |
| `cargo-target\release\cmfd-consensus.exe` | Exact feature-gated verifier/prover binary used. |
| `PRODUCTION-V3-QUALIFICATION-MANIFEST.json` | SHA-256 bindings for source, tool, inputs, proof, reports, journal, and exact logs. |
| `PRODUCTION-V3-ACTIVATION-CANDIDATE.json` | Non-activating pointer to the manifest and fresh-verifier report digest. |

The manifest records the source commit, the exact bank, Record V2, request,
proof, producer report, journal, verifier report, executable, stdout, and
stderr hashes. It also records both process IDs and the free-space floor,
margin, and observed free bytes. Input hashes are captured before their
verified use and recomputed during finalization, so a file changed after the
producer or verifier consumed it blocks the candidate.

The candidate intentionally uses
`CMFD_PRODUCTION_V3_ACTIVATION_CANDIDATE_V1`, not the release gate's activation
schema, and sets `eligible_for_automatic_activation` to `false`. Do not rename
it to `PRODUCTION-V3-ACTIVATION.json`. Promotion requires independent review,
committing the approved evidence, and a separate source change to the compiled
RCNet-1/ProductionV3 selection. Its `qualification_source_commit` is the commit
that built the measured verifier. A later trusted release build supplies its
own checked-out commit dynamically; no source constant may claim its own future
commit hash.
