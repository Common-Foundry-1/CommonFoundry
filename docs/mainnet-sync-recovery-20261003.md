# Mainnet block-download timeout recovery

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
only after a block is locally validated or already known. A side-block hint leads
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
