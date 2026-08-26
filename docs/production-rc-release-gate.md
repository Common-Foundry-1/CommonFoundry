# Production RC release gate

Production release-candidate labels are fail-closed. A build is treated as a
production RC when `cmfd-node` is built with the `production-rc` feature, when
`CMFD_RELEASE_LABEL` names a production/mainnet RC, when the package version is
a non-Devnet RC, or when GitHub builds a matching production-RC ref. Devnet and
testnet RC labels are deliberately excluded.

The build proceeds only when the source-selected profile is RCNet, its consensus
proof selector is `ProductionV3`, and the compiled profile contains complete
activation evidence: the qualification source commit, qualification-manifest
SHA-256, fresh-process verifier binary SHA-256, and fresh-process verifier report
SHA-256. A production build must also receive the exact release checkout as
the trusted `CMFD_BUILD_SOURCE_COMMIT` input. It must also pin the exact byte
length, BLAKE3 digest, and SHA-256 digest of the production bank, manifest, and
Record V2, plus distinct Windows x86-64 and Linux x86-64 SHA-256 identities for
the packaged persistent `cmfd-proof-worker`. The qualification evidence's
`fresh_process_verifier_binary_sha256` identifies the `cmfd-consensus`
qualification harness and must not be reused as the runtime-worker pin. The
current source selection is Devnet/V2 with no activation evidence, artifact
pins, runtime-worker pins, or final production-network identity pin, so this
command must fail:

```text
cargo check --locked -p cmfd-node --features production-rc
```

Release finalization applies a second, artifact-level check. Any production-RC
stage must inventory `NETWORK-INFO.json`, `RCNET-LAUNCH-CANDIDATE.json`,
`PRODUCTION-V3-ACTIVATION.json`, the actual
`PRODUCTION-V3-QUALIFICATION-MANIFEST.json`, the exact
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER.bin`, and its
`PRODUCTION-V3-FRESH-PROCESS-VERIFIER-REPORT.json`. The compiled manifest must
identify RCNet-1, select `ProductionV3`, bind the checked-out release commit
provided by the trusted build job, and bind the exact activation-evidence bytes
by SHA-256.

`cmfd-node rcnet-candidate` creates the launch-candidate file without
overwriting an existing path. It accepts the canonical final Record V2 and
explicit timestamp, bootstrap, port, proof-of-work limit, and reward
destinations. Its launch root binds those values, every compiled consensus and
economic parameter, and the Record V2/model identities. The network ID and
virtual genesis are independently derived from that root under distinct
BLAKE3 domains; neither derived value is an input to the root.

The finalizer recomputes SHA-256 over the staged qualification manifest,
fresh-process verifier binary, and fresh-process verifier report and requires
exact matches in the activation evidence. It also checks that the qualification
manifest binds the staged verifier artifacts, the pinned Cargo and rustc
binaries, the generated Cargo configuration, production n=33/134-claim
geometry, an RCNet-1 qualification identity, and a successful fresh-process
same-build verifier report. This is process isolation, not an independently
built verifier claim. Arbitrary well-formed nonzero digest strings cannot pass.
These files then become ordinary hashed release artifacts in `BUILDINFO.json`
and `SHA256SUMS.txt`.

Both build and finalization gates reject zero or repeated-byte network/genesis
identities, RFC 5737 documentation bootstraps, and the known deterministic
Devnet reward keys. Finalization additionally requires the compiled network
manifest to match the candidate's identity, timestamp, services, difficulty
limit, rewards, and Record V2 identity. The current RCNet constants remain
placeholders and therefore cannot pass these checks.

For the binary-only RC, finalization also pins the service allocation to RPC
`19443`, P2P `19444`, and pool `19445`; rejects source-like top-level release
assets; and requires the wallet JavaScript package, Tauri package/config, node,
miner, and proof-worker manifests that produce shipped applications to carry
the exact same non-Devnet RC version supplied to the finalizer. Internal
library crates retain independent semantic versions. Runtime policy keeps RPC
loopback-only. Release launchers and firewall instructions must expose only TCP
`19444`; they must not start or expose the pool service on `19445`.

These checks do not sign binaries or `SHA256SUMS.txt`, generate an SBOM, inspect
the contents of GitHub's automatically generated source archives, or distribute
the multi-gigabyte model bank. Those are separate release gates. A public
binary repository must contain only reviewed binary-release metadata, and the
model bank must be delivered through a create-new partial download that checks
the compiled byte length, BLAKE3, and SHA-256 pins before atomic publication.
The node then authenticates the bank, manifest, and Record V2 again before
opening chain storage.

The qualification manifest records the older exact commit used to build and
run the qualifying verifier. The final activation evidence separately records
the release checkout commit supplied as trusted CI input. This avoids the
impossible requirement for a committed source constant to contain its own
future commit hash; the release finalizer matches the dynamic build identity to
the checked-out commit.

Changing a label, branch name, archive name, or package name cannot satisfy
these checks. Activation requires the real profile/proof integration and the
committed qualification evidence; no override or fallback flag exists.

## Runtime sidecar contract

An activated RC node or wallet launched without artifact arguments resolves one
fixed layout relative to its own executable directory:

```text
cmfd-node[.exe] or common-foundry-wallet[.exe]
cmfd-proof-worker[.exe]
production-v3/MODEL-V2.bank
production-v3/MODEL-V2.manifest.json
production-v3/DORY-V3-MODEL-RECORD-V2.json
```

Every path is canonicalized and must be a regular file. The existing compiled
byte-length/BLAKE3/SHA-256 artifact gates authenticate the three model files.
The selected platform's compiled worker SHA-256 authenticates the sidecar.
Explicit paths are accepted only as one complete set and still must match those
compiled identities. Startup never downloads, discovers, or invents a missing
artifact.

The worker hashes while copying the sidecar into a private runtime directory,
synchronizes and makes that copy non-writable, then rehashes immediately before
each execution. Source metadata and the streaming copy are both bounded to 512
MiB so a mismatched package path cannot fill the runtime disk before its digest
is rejected. Retained exact-object handles prevent same-user replacement of the
configured worker and private image through mapping and process lifetime. They
do not pin transitive dynamic libraries; package ACLs/signatures remain a
release responsibility.
Request timeouts and process teardown terminate the contained process tree and
never wait indefinitely for an inherited pipe reader. A pipe owner that somehow
survives containment is detached and cannot yield a trusted response or
capability; repeated containment escapes remain an operating-system and package
trust concern rather than a consensus fallback.

The worker pin is not source-circular with the node profile: the worker does not
depend on `cmfd-node`, its release-profile constants, or
`CMFD_BUILD_SOURCE_COMMIT`. The ceremony must nevertheless freeze its source,
dependencies, features, versions, toolchain, target, and compiler flags; build
and hash the ProductionV3 worker independently on Windows and Linux; insert only
those hashes into the node profile; then rebuild both workers from clean target
directories and require byte-identical hashes before building node/wallet
packages.

The parent still performs retained-handle, two-pass artifact authentication to
construct the parameter authority used for proof-free consensus checks. It
does not verify ProductionV3 proofs. The persistent worker starts and completes
its authenticated handshake before the data-directory lock is acquired and
before block-log replay. Every replayed ProductionV3 block is sent through that
worker and receives a fresh, process-local capability bound to its exact
canonical statement; no capability is trusted from disk.

Live active-chain and side-branch admissions also require the external
capability. A side-branch request captures an immutable ancestry tip and chain
revision under the node mutex, reconstructs and preflights the branch outside
that mutex using only the already issued capabilities, then rechecks the exact
revision, block, parent, and acceptance time before the authoritative commit.
Any concurrent block commit makes the admission stale and retryable. Devnet
keeps its existing in-process V2 path. The parent and worker each authenticate
the model artifacts once at startup, so this is still not a single global
artifact load, but ProductionV3 proof verification itself is external-only and
bounded by the persistent-worker controls.

Remote ProductionV3 submission is additionally bounded by an eight-session
active-plus-waiting FIFO with a 60-second admission limit. The shared proof
queue remains one active/eight normal waiters with a five-second queue limit,
while locally found blocks retain a separate two-waiter priority lane. Cached
proofs still take their remote FIFO turn. Node status exposes per-class active,
queued, wait, rejection, and post-dispatch proof-failure counters plus the
remote capacity and wait limit.

The release protocol fixes one end-to-end `SubmitBlock` contract: mining and
relay clients wait up to 120 seconds, server acceptance ends at 110 seconds,
and the server response cutoff is 115 seconds. Disconnect/deadline and commit
race through one atomic `Active -> Cancelled | Committing` transition at the
durable append boundary. Cancellation wins without mutation; committing wins
only after a post-CAS deadline recheck and by completing durability and state
commit or latching a storage fault.
The 115-second cutoff covers the status lock, serialization, and every socket
write. Queue expiry, capacity exhaustion, and worker restart/unavailability
produce retryable `Busy`; cryptographic invalidity produces `Rejected`. The
miner retains the identical ProductionV3 block and proof across compatible
reconnects for one interruptible 20-minute total budget; `Busy` alone never
causes a fresh template. Tip changes and budget abandonment have separate
logs and counters. Shutdown interrupts bounded connect attempts, handshake,
request writes, response reads, and retry waits. Transport disconnect and peer
protocol-error telemetry are separate from cryptographic rejection. A faulted
generation is restarted only by the single-flight supervisor outside the
remote request, cannot resurrect after terminal close, and is not admitted
until startup authentication has succeeded.

The current 2 GiB worker memory-limit default is a containment setting, not a
qualified production requirement. The final Windows and Linux package smoke
must authenticate the real bank under the configured job/address-space limit,
record peak RSS/commit and startup time, and raise or otherwise qualify the
default before activation.

The current Tauri/CI finalizer does not yet stage or inspect this runtime
sidecar layout. A real ProductionV3 package is therefore still blocked until
the final artifacts exist and packaging compares the staged worker bytes to the
compiled `NETWORK-INFO.json` pin on both platforms. Unit package-layout fixtures
do not substitute for that final packaged smoke test.

## Runtime verifier sandbox gate

Process-tree and memory containment alone are not sufficient for a parser that
handles hostile ProductionV3 proofs. The Linux x86-64 worker must install
Landlock ABI 3 or newer and the compiled default-deny seccomp policy before it
reads/loads model artifact contents or any untrusted IPC frame. The worker
receives an empty environment and only standard protocol pipes across `exec`.
Landlock grants read access only to the exact bank, manifest, and Record V2 and
denies handled filesystem mutation and execution rights. The retained validator
needs directory-open access on dedicated artifact-parent subtrees; directory
enumeration is denied, but guessed pathname/stat metadata is not hidden. ABI 3
does not mediate network access, so it is accepted only together with a seccomp
allowlist limited to artifact reads, bounded stdio, allocation, clocks, and the
Rust/Rayon runtime.
The exact pthread clone mask is the only process-creation primitive and every
unlisted syscall returns `EPERM`. Failure to establish either control aborts
startup before replay or P2P.

This Linux checkpoint does not yet provide a per-worker CPU/PID budget.
`RLIMIT_NPROC` is per real UID, and an allowed pthread can outlive a completed
request inside the persistent worker. Release remains blocked until delegated
cgroup v2 limits or an equivalently fail-closed, race-bounded watchdog enforce
the budget for this worker rather than for the operator account as a whole.

The Windows isolation implementation now creates the verifier suspended in a
zero-capability LPAC through one `STARTUPINFOEX` call. Its attribute list
contains the documented LPAC opt-out, the preconfigured kill-on-close Job,
exactly six inherited handles, child-process restriction, and Win32k and other
process mitigations. Only bounded stdio and three parent-owned read-only
artifact handles cross the boundary; the Windows worker has no artifact
pathname fallback. The parent validates the resulting token, capability count,
SID, DEP, ASLR, dynamic-code, image-load, Win32k, child-process, SEHOP,
strict-handle-check, and extension-point mitigations, Job membership, and exact
limits before resuming the primary thread. It also fails closed if the exact
new profile SID appears in the system loopback-exemption table. It never
mutates the shared configured executable or directory ACL. Every launch gets a
fresh private
directory and regular executable copy; no-write/no-delete-share handles pin the
source, exact hash/length-verified destination, and directory through image
mapping and process lifetime. Reparse or hardlink ambiguity fails closed, only
the private objects receive the unique SID, and the worker executes only that
verified path. After confirmed process-tree exit, the exact private file and
directory are marked for deletion through their retained `DELETE` handles,
bound by full 128-bit `FILE_ID_INFO`. An added alias, replacement, unconfirmed
exit, or uncertain cleanup retains or quarantines all relevant pins and latches
worker health.

A protected owner-only ledger records a durable ownership intent before
`CreateAppContainerProfile`. Only its live same-process guard can delete the
registration. Deletion uses bounded delays of `0, 10, 20, 40, 80, 160, 320,
500 ms`; exhausted deletion or marker cleanup is surfaced and remains
retryable on that guard. Initialization failures retain quarantine evidence.
No later process deletes a profile from a persisted name; any stale session,
including an empty partial session, blocks launch for manual remediation.
Successful creation is wrapped in that RAII guard before SID validation or
another fallible step, and forced-panic subprocess regressions require exact
before/after profile-mapping and temporary-root `FILE_ID_INFO` sets. A fresh
allowlisted UTF-16 environment replaces ambient inheritance. The native
sentinel covers supplied-handle reads, artifact and arbitrary-file data and
metadata denial, exact `WSAStartup` failure 10107, and denial of a real
`WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP)` request. No socket handle is
inherited, so the production LPAC never reaches a genuine `connect`, `bind`, or
`listen` call. A second, explicitly less-restricted regular AppContainer probe
uses the same zero-capability, non-loopback-exempt profile but initializes
Winsock and creates its own valid sockets. On the qualification host, a bounded
outbound connection to the parent's concrete non-loopback listener never
completes and the parent accepts nothing. Although local `bind` and `listen`
setup succeed, a parent connection to that listener times out, the child accepts
nothing, and the endpoint is reusable after teardown. This is measured
same-host evidence, not production-token evidence and not a substitute for the
packaged external-host network gate. Neither path grants a registry or network
capability.

The external-host gate must run the packaged binary on the qualification host
against a separately routed fleet peer. The packaged production LPAC must
repeat its exact Winsock-init/socket-creation denial. Its zero-capability
regular AppContainer companion must attempt an outbound connection to a
peer-owned listener while the peer records no accept or traffic, then create a
concrete non-loopback listener while the peer attempts to connect and the child
records no accept or traffic. Both directions require bounded poll/`SO_ERROR`
results, the exact profile SID and no-loopback-exemption attestation, and proof
that the endpoint is reusable after child teardown. Any connection, accept,
payload, ambiguous timeout, or missing capture fails the gate. The external
harness and signed evidence do not yet exist; this is an explicit release
blocker, not a completed qualification claim.

Sockets created outside an AppContainer can retain authority when inherited.
The exact six-handle list is therefore an enforced boundary: production and
both sentinels reject any extra handle before creation, and the regression uses
a real socket as the forbidden seventh handle. The native sentinel also covers
child creation and ambient environment. Kill-on-last-Job-handle evidence uses
an inherited-stdio `READY`/`ARMED` barrier; immediately before close, the
parent requires a nonsignaled process and exact Job accounting of one active
process. Only the measured zero Job-close exit status passes.
`STATUS_INVALID_HANDLE`, an arbitrary exception, and any pre-close exit fail.
Process error mode and WER no-UI flags suppress interactive crash dialogs while
retaining exact status diagnostics. No `TerminateJobObject` call is used in
this sentinel path. Its omitted-file check is a trusted parent-side
`DuplicateHandle` probe while the child is suspended: only
`ERROR_INVALID_HANDLE` passes, and numeric-slot reuse is an explicit failure.
The child also queries its own process heap before artifact/IPC reads and
requires the exact enabled terminate-on-corruption state.

Neither platform is qualified by unit tests alone. Release evidence must show
the packaged worker reading the real pinned artifacts, completing the startup
handshake, accepting one known-valid ProductionV3 block, rejecting corruption,
and passing file read/write, metadata mutation, network, process-spawn,
unlisted-handle, environment, and teardown escape sentinels. Linux currently
has the kernel-policy and sentinel implementation; its real-bank packaged run
and per-worker CPU/PID containment are still outstanding. Windows now has the
launcher, native escape sentinel, and a real-worker integration that passes
authenticated deliberately small artifacts through the launcher and reaches
their expected format rejection. It does not yet have the packaged real-bank,
known-valid/corrupt-block replay, external-peer bidirectional network-isolation
run, or independent release evidence. Therefore
this checkpoint must not activate RCNet or be described as cross-platform
RC-ready.
