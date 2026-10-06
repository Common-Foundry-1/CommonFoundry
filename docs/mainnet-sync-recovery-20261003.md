# Mainnet block-download timeout recovery

The next branch-state update retains bounded, process-local validated state
between competing blocks and completed replay slices. A later child can resume
from its verified ancestor instead of rebuilding state from genesis again.
Recent active-state anchors are sampled every 16 blocks, at startup, and after
an accepted reorganization, only
when eligible for the checked memory budget. Checkout moves checkpoint state;
it does not clone it. Active-anchor creation is the only bounded state clone.

The cache holds at most four entries and an estimated 128 MiB of retained state.
This heuristic is not a total-process RSS limit: checked-out reconstruction
state, the active state, shared verifier allocations and allocator overhead are
separate. Existing admission bounds and operator memory limits still apply.
Eviction or lock contention can discard progress and cause safe cold replay.
Cancellation never grants permission to commit an expired candidate.

Checkpoints are private in-memory values bound to the exact node, network,
consensus fingerprint and verifier generation. Reuse checks the indexed anchor,
state/header agreement, path endpoints, retained log identity and extent, and
the authenticated V2 anchor record. Every replayed suffix record and every new
candidate still undergoes its normal validation. Skipped prefix bytes are not
reread on every reuse: this retains already trusted state, like ordinary active
extension. Startup anchors inherit the existing authenticated startup-snapshot
trust; no remote snapshot or raw persisted delta becomes a new authority.

Tests cover repeated competing forks with transactions and advancing tips,
cancellation before/after a replay slice, queue failure after checkout, stale
contexts, invalid bodies, corrupted anchors, bounded cache eviction, and short
forks from a recent active anchor. An explicitly opted-in, ignored CPU-only test
also accepts six preserved real mainnet block frames and authenticated public
launch inputs, compares cold and warm branch admission, and checks the resulting
state against a fresh independent replay. Its fixture output is isolated from
operator wallets and live node data. This is not a claim of live multi-pool load
qualification or a guarantee that every future fork will recover promptly.

The sync.4 follow-up also preserves continuation through already-known active
blocks. A sparse locator can skip the actual shared fork point. With a one-block
batch, the peer then returns a known active ancestor before the competing branch.
Ignoring that active cursor repeated the same ancestor forever without requesting
the next block. Any locally validated non-genesis cursor now leads the next
locator, with duplicates removed and the bounded active-chain/genesis fallback
retained. The regression uses 16 shared blocks followed by competing branches;
it fails on the second poll before the fix and then advances through three known
blocks and fourteen new blocks to the exact stronger-chain tip afterward.

The sync.3 follow-up distinguishes intrinsic invalid transactions from local
chain/mempool policy rejections when scoring a peer. Missing or immature inputs,
conflicts and local policy differences must not ban an honest ahead peer during
catch-up. Transaction acceptance rules are unchanged; intrinsic key-signature and
wire/protocol protections remain, and logs include the actual rejection cause.

Ancestor reconstruction also consults the existing generation-bound successful
proof cache. Every cache miss still executes the real verifier, and successful
evidence is retained immediately so a canceled retry does not repeat all prior
proof work. Durable records are still authenticated and every transaction/state
transition is checked. The cache remains process-local and bounded at 1,024
entries; this is not an unbounded-history state-checkpoint mechanism.

A serving peer previously returned a requested block, then applied its ordinary
10-second idle timeout while the receiver verified the proof or reconstructed
fork state. The receiver treated that disconnect like cancellation of an
unsolicited submission, discarded the completed download, and retried the same
block. Its generic cancellation error could appear as a proof-capacity timeout.

An additional starvation bug affected competing branches longer than the per-
session block batch. The active-chain-only locator omitted validated side-chain
progress, so a one-block mainnet batch could request the same known prefix forever.
Each outbound peer now retains a bounded, runtime-only continuation hint, updated
only after a block is locally validated or already known. The validated hint leads
the next locator, followed by an active-chain fallback and genesis. Concurrent
sessions cannot overwrite a newer hint with stale state. After restart the first
known prefix rebuilds the hint; no chain data is erased or trusted from the peer.
One-sided push relay separately retains the last acknowledged block. It resumes
the next bounded push from that block, clearing the hint if the receiver rejects
the continuation. Acknowledgements never determine local chain selection.

The serving side now allows the existing bounded 120-second block-processing
budget for the next message after serving a block. The overall session deadline,
message/byte limits and shutdown cancellation remain enforced.

The receiving side independently validates a fully received, explicitly requested
block even if its source disconnects. Local shutdown and the fixed admission
deadline still cancel validation. Unsolicited `SubmitBlock` requests retain their
disconnect-cancellation rules. There is no wire-protocol, proof, chain-work,
network identity, monetary-policy or wallet-format change.

Regression coverage reproduces the discarded-download failure before the fix
and checks source disconnects, slow validation, local shutdown, the total session
deadline and existing unsolicited-submission cancellation. A stalled node should
retain its existing data and wallet when installing a verified signed update.
Do not erase blocks or select a branch based on height alone.
