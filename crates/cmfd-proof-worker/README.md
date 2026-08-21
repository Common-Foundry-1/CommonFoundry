# Common Foundry proof worker

`cmfd-proof-worker` places optional CUDA proof generation in a short-lived
child process. The parent names absolute worker and CUDA-library paths, hashes
both files with caller-supplied SHA-256 pins, sends one bounded canonical binary
request, enforces a timeout and output limits, and kills the child on failure.
The worker independently rehashes the CUDA library immediately before loading
it. A returned proof is never accepted until the parent runs the unchanged
`verify_structured_blake3` CPU verifier over the exact response bytes.

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
