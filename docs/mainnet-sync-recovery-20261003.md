# Mainnet block-download timeout recovery

A serving peer previously returned a requested block, then applied its ordinary
10-second idle timeout while the receiver verified the proof or reconstructed
fork state. The receiver treated that disconnect like cancellation of an
unsolicited submission, discarded the completed download, and retried the same
block. Its generic cancellation error could appear as a proof-capacity timeout.

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
