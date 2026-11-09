//! Operator-facing timing events. These never change share or proof validation.

#[cfg(any(feature = "production-v4", test))]
pub(crate) struct ProofTiming {
    pub network_id: [u8; 32],
    pub height: u64,
    pub parent: [u8; 32],
    pub nonce: u64,
    pub search_replay_seconds: f64,
    pub full_replay_seconds: f64,
    pub replay_handoff_seconds: f64,
    pub proof_seconds: f64,
    pub pool_evaluation_wall_seconds: f64,
    pub proof_bytes: usize,
}

#[cfg(any(feature = "production-v4", test))]
impl ProofTiming {
    pub fn record(&self) {
        tracing::info!(
            network_id = %hex::encode(self.network_id),
            height = self.height,
            parent = %hex::encode(self.parent),
            nonce = self.nonce,
            search_replay_seconds = self.search_replay_seconds,
            full_replay_seconds = self.full_replay_seconds,
            replay_handoff_seconds = self.replay_handoff_seconds,
            proof_seconds = self.proof_seconds,
            pool_evaluation_wall_seconds = self.pool_evaluation_wall_seconds,
            proof_bytes = self.proof_bytes,
            "pool proof timing"
        );
    }
}

pub(crate) struct AcceptanceTiming {
    pub network_id: [u8; 32],
    pub height: u64,
    pub parent: [u8; 32],
    pub block_id: [u8; 32],
    pub nonce: u64,
    pub share_evaluation_seconds: f64,
    pub node_submission_seconds: f64,
    pub total_acceptance_seconds: f64,
}

impl AcceptanceTiming {
    pub fn record(&self) {
        tracing::info!(
            network_id = %hex::encode(self.network_id),
            height = self.height,
            parent = %hex::encode(self.parent),
            block_id = %hex::encode(self.block_id),
            nonce = self.nonce,
            share_evaluation_seconds = self.share_evaluation_seconds,
            node_submission_seconds = self.node_submission_seconds,
            total_acceptance_seconds = self.total_acceptance_seconds,
            "pool block accepted timing"
        );
    }
}
