# Common Foundry proof worker

`cmfd-proof-worker` places optional CUDA proof generation in a short-lived
child process. The parent names absolute worker and CUDA-library paths, hashes
both files with caller-supplied SHA-256 pins, sends one bounded canonical binary
request, enforces a timeout and output limits, and kills the child on failure.
The worker independently rehashes the CUDA library immediately before loading
it. A returned proof is never accepted until the parent runs the unchanged
`verify_structured_blake3` CPU verifier over the exact response bytes.

The same process boundary supports block-proof verification in one persistent
worker per node. Before P2P starts, the node copies the pinned executable into a
private random runtime directory, starts it under the memory limit, and requires
an exact profile, network, verifier-identity, sandbox-status, and
challenge-response self-test.
For ProductionV3 the worker authenticates the bank, manifest, and Record V2 once
at startup. It then handles bounded canonical block requests sequentially; the
node's admission queue permits one active request and only a bounded number of
waiters. No ProductionV3 failure can select the V2 Devnet verifier.

Each request has its own deadline and response bounds. Timeout, crash, malformed
protocol, identity mismatch, or internal worker failure kills that process tree
and rejects the candidate. The next request may start only a new worker that
passes the complete startup handshake. A canonical invalid-proof response is
statement-local and does not poison an otherwise authenticated generation.
Explicit shutdown uses a separate process-tree handle, so it does not wait
behind an in-flight request. Stderr is retained only through 64 KiB. On the
first excess byte the reader closes and marks that generation as overflowed;
an in-flight or subsequent exchange rejects it and terminates the process tree,
and shutdown remains the final teardown path while the worker is idle.

The hash-pinned worker path has been exercised end to end with a 64-byte tree
proof using the wired CUDA DFT/LDE and value-MMCS Poseidon2 first-digest path.
The corresponding direct in-process API remains a trusted-development
interface only.

At the 32,768-row checkpoint on an RTX 5090, an unoptimized Cargo test-profile
CPU run took 348.28 seconds (64.503 setup, 283.416 prove; 238,698-byte canonical
zlib payload). CUDA DFT plus Poseidon2 took 76.71 seconds (7.700 setup, 68.551
prove; 237,292 bytes), a 4.54x speedup and 78% less wall time. Verification
remained on the unchanged CPU path.

Every spawn is contained in a new Unix process group or a Windows Job Object
with `KILL_ON_JOB_CLOSE`. Timeout, output overflow, and parent cleanup terminate
the contained process tree so a worker descendant cannot survive by retaining
an inherited pipe handle. Verifier mode also sets a Unix address-space limit
or Windows per-process and aggregate-job memory limit.

The request contains only a `StructuredBlake3Statement` and final activation.
CUDA library selection, its hash pin, and the device index are explicit process
arguments; there is no environment or default-path selection and no CPU
fallback after CUDA is selected.

The CUDA prover and Devnet V2 verifier boundaries isolate ordinary crashes and
many worker OOM failures from the parent. They are **not OS sandboxes**. The
verifier runtime copy is hashed
while it is copied, synchronized, made non-writable, and hashed again immediately
before every execution. Both source metadata and bytes actually copied are
bounded to 512 MiB. Its random directory is mode `0700` on Unix; Windows inherits
the user's temporary-directory ACL and marks the file read-only. This narrows
but does not eliminate a same-user check/exec race: the same user or an
administrator can restore write access between the final hash and process
creation, and the operating-system loader can still resolve an unpinned dynamic
dependency after the executable check.
Production packaging must use OS ACL/signing controls if that attacker is in
scope. CUDA proof generation retains its separate caller-pinned DLL boundary.
For proof generation the parent independently verifies returned proof bytes.
For verifier mode, repeating verification in the parent would defeat the
isolation, so the pinned worker outcome is explicitly trusted after the exact
statement-bound protocol checks.

ProductionV3 block verification has a stricter fail-closed boundary. On Linux
x86_64, the child opens the three trusted paths for setup, then must install the
following controls before reading/loading artifact contents or an untrusted
request:

- `PR_SET_NO_NEW_PRIVS` and non-dumpable process state;
- Landlock ABI 3 or newer, granting file-content read access only to the exact
  bank, manifest, and Record V2 files. The retained pathname validator also
  needs directory-open rights on each artifact parent's recursive subtree, so
  release packaging must use dedicated mode-`0700` parent directories with no
  unrelated entries. Seccomp denies `getdents`/`getdents64`, so the worker
  cannot enumerate those directories;
- a default-deny seccomp allowlist for retained artifact reads, bounded stdio,
  allocation, clocks, and Rust/Rayon runtime calls. `clone3` is forced to the
  legacy path, and `clone` accepts only the exact pthread flag mask; network,
  process execution, filesystem/metadata mutation, cross-process resource or
  affinity inspection, namespaces, mounts, IPC, io_uring, keyrings, and every
  unlisted syscall fail. Read-only `stat`-family calls remain available for the
  retained validator, so guessed host pathname metadata is not hidden;
- an empty environment, only stdin/stdout/stderr inherited across exec, the
  address-space limit, an at-most-64-descriptor hard limit, a narrowed
  per-real-UID task limit, process-group teardown, parent-death signal, wall
  deadline, and bounded output. Root, set-ID, and capability-bearing worker
  identities are rejected.

Landlock ABI 3 does not mediate network access. It is sufficient here only in
combination with the mandatory seccomp socket/network denial. ABI 4 and newer
also enforce TCP bind/connect denial in Landlock. An older Landlock ABI, a
sandbox-status mismatch, or any sandbox setup error aborts ProductionV3 startup
before P2P is enabled. A legitimate runtime syscall omitted from the allowlist
returns `EPERM`, so real-bank package qualification is mandatory before release.

Windows ProductionV3 now uses a direct
[`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
`STARTUPINFOEX` launch. The process is created suspended with a unique
zero-capability AppContainer profile, the documented
`PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT` attribute for LPAC, an
exact six-handle inheritance list (bounded protocol stdio plus three retained
read-only artifacts), and an atomic Job list. The Job has kill-on-close, exact
process/job memory limits, and an active-process limit of one. Child-process
and Win32k mitigations are applied in the same attribute list. The parent
re-queries the token, zero capability count, exact AppContainer SID, DEP, ASLR,
dynamic-code, image-load, Win32k, SEHOP, strict-handle-check, extension-point,
and child-process policies, Job membership, and Job limits before resuming the
primary thread. Before reading artifact contents or IPC, the child queries its
own process heap and requires the exact enabled
`HeapEnableTerminationOnCorruption` state; query failure or a disabled state
fails closed. It also queries the system loopback-exemption table and fails
closed if the exact new profile SID is exempt. The launcher never changes the
configured executable or directory ACL. It opens the source without
write/delete sharing, rejects
reparse points and hardlink ambiguity, copies into a fresh per-launch
directory, verifies the exact destination object's pinned SHA-256 and length,
and retains the source, destination, and directory handles through process
lifetime. Only those new private objects receive the unique AppContainer SID;
`CreateProcessW` executes only the verified private path. After confirmed
process-tree exit, the parent marks the exact private file and directory for
deletion through their retained `DELETE` handles. Each handle is bound with
the full 128-bit `FILE_ID_INFO`; replacement, reparse, or added-hardlink
ambiguity fails closed. An unconfirmed exit or uncertain exact-object cleanup
retains the process, Job, profile, and runtime pins and permanently blocks new
worker launches in that process.

Before `CreateAppContainerProfile`, a protected owner-only ledger records the
unique name as a durable ownership intent. Only the live same-process guard
created from that intent may delete the registration. Profile deletion uses
the bounded delays `0, 10, 20, 40, 80, 160, 320, 500 ms`; exhausted deletion or
marker cleanup remains retryable on that guard. Marker initialization and
cleanup failures latch worker health and retain quarantine evidence. A later
process never deletes an AppContainer profile from a persisted name: any stale
session, including an empty partial session, blocks launch for manual
remediation. Every successful profile creation is immediately placed in this
RAII ownership before SID validation or another fallible step; panic
subprocess regressions compare the exact CMFD registry mapping and randomized
temporary-root `FILE_ID_INFO` sets before and after unwinding. See
Microsoft's primary documentation for
[`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[`CreateAppContainerProfile`](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile),
[`GetTokenInformation`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation),
and [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

The worker receives no pathname fallback and independently re-authenticates
the object identity, length, BLAKE3, and SHA-256 of each inherited artifact
handle before the consensus loader consumes it. Its environment is a newly
constructed, sorted, double-NUL UTF-16 allowlist derived from a fresh
[`CreateEnvironmentBlock`](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock)
source; a null environment pointer is never used. The headless worker is a
Windows-subsystem executable and all normal protocol and diagnostics still use
the explicit stdio handles.

On Windows build 26200, the documented `TokenIsLessPrivilegedAppContainer`
information class returned `ERROR_INVALID_PARAMETER` for both fixed-size and
sizing queries. The launcher therefore does not claim a successful query of
that class: it requires the documented LPAC opt-out attribute and the native
behavioral sentinel proves denial of arbitrary file data and metadata access,
artifact mutation, exact `WSAStartup` error 10107, and denial of a real
`WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP)` request. The LPAC therefore
never owns a socket on which `connect`, `bind`, or `listen` could genuinely be
called. A separate, less-restricted regular AppContainer sentinel uses the same
new zero-capability, non-loopback-exempt profile and the same exact six
non-socket inherited handles. It initializes Winsock and creates its own valid
sockets. On the qualified host, its bounded outbound connection to a concrete
parent listener never completes and the parent accepts nothing. Its local
`bind` and `listen` setup calls succeed, but a parent connection to that live
listener times out, the child accepts nothing, and the endpoint is reusable
after teardown. These are precise same-host observations, not a claim that the
regular AppContainer is the production LPAC or a substitute for the packaged
external-host network gate. No registry or network capability is granted.

That remaining gate must use the packaged binary on the qualification host and
a separately routed fleet peer. The packaged production LPAC must repeat its
exact Winsock-init/socket-creation denial. Its zero-capability regular
AppContainer companion must attempt an outbound connection to a peer-owned
listener while the peer records no accept or traffic, then create a concrete
non-loopback listener while the peer attempts to connect and the child records
no accept or traffic. Both directions require bounded poll/`SO_ERROR` evidence,
the exact profile SID and no-loopback-exemption attestation, and endpoint reuse
after teardown. A connection, accept, payload, ambiguous timeout, or missing
capture fails the gate. This external-peer harness and evidence are not yet
complete, so ProductionV3 release remains blocked on them.

The inherited handle list is security-critical: a socket created outside an
AppContainer can retain authority when inherited. Production and both
sentinels therefore reject any seventh handle before process creation; a
regression supplies a real socket as the extra-handle case. The native sentinel
also covers child creation and ambient environment. Its child reports `READY`,
accepts `ARM` over the already-authorized stdin channel, reports `ARMED`, then
blocks on that channel. Immediately before closing the final kill-on-close Job
handle without calling `TerminateJobObject`, the parent requires the process
to be nonsignaled and Job accounting to report exactly one active process.
Only the qualified host's exact zero Job-close exit code is accepted;
`STATUS_INVALID_HANDLE` and every other pre-close/post-handshake crash are
rejected. The executable and libtest parents set
`SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX`, and each worker/sentinel entry
sets `WER_FAULT_REPORTING_NO_UI`, so the exact fault status remains diagnostic
without opening an interactive dialog.
For an omitted inheritable file, the trusted parent probes the suspended
child's exact numeric slot with `DuplicateHandle` before resume and requires
`ERROR_INVALID_HANDLE`; an inherited identity, another file identity, or
non-file numeric-slot reuse all fail the sentinel. This closes the Windows isolation implementation
tranche only. ProductionV3 activation stays closed pending external-host
inbound/outbound qualification of the packaged worker, packaged real-bank and
known-block qualification, independent review, and the other release gates.

The Linux sandbox is designed to contain a verifier compromised by hostile
proof input, and its current sentinels cover file-content reads, file and
metadata mutation, network, process creation, broadened clone flags, unlisted
syscalls, environment and descriptor inheritance. It does not conceal general
pathname metadata or protect against an administrator, kernel compromise, or
another process already running as the wallet user modifying package bytes.
The per-real-UID task limit is not a per-worker CPU/PID boundary: a compromised
persistent worker may retain allowed pthreads after responding. Dedicated
per-worker CPU/PID enforcement remains a production release gate. This is one
checkpoint, not a claim that the consensus implementation is ready for
mainnet.

The independent `proof_stream` ABI v1 copies ordered canonical
physical-bit-reversed source coefficients to the GPU once and then advances a
strict global physical-row cursor. It supports 1-64 equal-height matrices, a
source height through `2^20`, zero to seven added bits, at most `2^27` expanded
rows, 4,096 total columns, and `2^31` input limbs. Each call requests a
power-of-two chunk no larger than `2^16` rows and cannot cross a source-height
coset block. It returns optional interleaved physical LDE rows and always
returns the matching unpadded four-limb Poseidon2 digests. At `32,768 x 291`,
`+7`, the digest-only stream phase measured 308.345 ms and 13.60 million rows/s
on an RTX 5090 while avoiding a 9.094 GiB host LDE.

`LdeArtifactWriter` drains a fresh stream sequentially into a unique
`.partial` file. It rejects skipped, repeated, incomplete, noncanonical, or
geometry-mismatched rows. The sealed v1 artifact binds the job identifier,
every ordered source-matrix width and coset shift, all aggregate LDE geometry,
physical-bit-reversed layout, declared byte length, and canonical little-endian
limbs with BLAKE3. Sealing requires every row, writes the authentication table
and checksum, synchronizes and validates the file, and then publishes without
overwrite. Normal failure or drop removes the partial artifact; abrupt process
termination can leave an unpublished `.partial` file for operator cleanup.
Opening a sealed artifact authenticates its header, exact length, and full
checksum. Every later random row read reauthenticates the fixed-size chunks it
uses and rejects noncanonical limbs.

The artifact checksum is storage-integrity metadata, not a consensus
commitment, and the CPU verifier remains authoritative. The current Plonky3 PCS
does not yet consume these sealed matrices: full out-of-core PCS/FRI processing,
Merkle construction and level storage, and opening generation remain
incomplete. This milestone is not production-ready.
