# Common Foundry proof worker

`cmfd-proof-worker` places optional CUDA proof generation in a short-lived
child process. The parent names absolute worker and CUDA-library paths, hashes
both files with caller-supplied SHA-256 pins, sends one bounded canonical binary
request, enforces a timeout and output limits, and kills the child on failure.
The worker independently rehashes the CUDA library immediately before loading
it. A returned proof is never accepted until the parent runs the unchanged
`verify_structured_blake3` CPU verifier over the exact response bytes.

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
an inherited pipe handle.

The request contains only a `StructuredBlake3Statement` and final activation.
CUDA library selection, its hash pin, and the device index are explicit process
arguments; there is no environment or default-path selection and no CPU
fallback after CUDA is selected.

This boundary isolates ordinary worker crashes and many worker OOM failures
from the parent. It is **not an OS sandbox**. In particular, it does not protect
against a same-user attacker replacing the worker, CUDA DLL, or a transitive
dependency between hashing and execution/loading. Production operators need an
OS-enforced sandbox and file/ACL isolation if that attacker is in scope.

CUDA ABI v1 is test-profile-only and caps each call at `2^24` rows and `2^31`
field limbs. Production uses `2^27` LDE rows; widths 291 and 87 would require
291 GiB and 87 GiB input matrices respectively, plus a 4 GiB digest layer.
Production therefore still requires streaming/out-of-core PCS, FRI, and Merkle
construction rather than this monolithic ABI.
