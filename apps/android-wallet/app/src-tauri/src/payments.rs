use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cmfd_wallet_core::{AddressCodec, AddressFormat, OutPoint, PaymentPlan, SignedTransaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_PENDING_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum PaymentStoreError {
    #[error("pending transaction state is unavailable")]
    Io,
    #[error("pending transaction state is invalid")]
    Invalid,
    #[error("payment confirmation no longer matches the prepared transaction")]
    ConfirmationMismatch,
    #[error("recipient presentation does not match the prepared transaction")]
    RecipientMismatch,
    #[error("payment intent or one of its inputs is already pending")]
    Duplicate,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentSummary {
    pub intent: String,
    pub recipient: String,
    pub recipient_hex: String,
    pub recipient_bech32m: Option<String>,
    pub amount_atoms: String,
    pub fee_atoms: String,
    pub change_atoms: String,
    pub input_atoms: String,
    pub selected_inputs: usize,
}

#[derive(Debug)]
pub struct PreparedPayment {
    pub plan: PaymentPlan,
    pub summary: PaymentSummary,
}

impl PreparedPayment {
    #[cfg(test)]
    pub fn new(plan: PaymentPlan) -> Self {
        let recipient_bech32m = plan.recipient_address();
        let summary = PaymentSummary {
            intent: hex::encode(plan.signing_digest()),
            recipient: recipient_bech32m.clone(),
            recipient_hex: hex::encode(plan.recipient),
            recipient_bech32m: Some(recipient_bech32m),
            amount_atoms: plan.amount_atoms.to_string(),
            fee_atoms: plan.fee_atoms.to_string(),
            change_atoms: plan.change_atoms.to_string(),
            input_atoms: plan.input_atoms.to_string(),
            selected_inputs: plan.selected.len(),
        };
        Self { plan, summary }
    }

    pub fn from_recipient(
        plan: PaymentPlan,
        recipient_text: &str,
    ) -> Result<Self, PaymentStoreError> {
        let recipient_text = recipient_text.trim();
        let (recipient, format) = AddressCodec::mainnet()
            .decode(recipient_text)
            .map_err(|_| PaymentStoreError::RecipientMismatch)?;
        if recipient != plan.recipient {
            return Err(PaymentStoreError::RecipientMismatch);
        }
        let summary = PaymentSummary {
            intent: hex::encode(plan.signing_digest()),
            recipient: plan.recipient_address(),
            recipient_hex: hex::encode(recipient),
            recipient_bech32m: match format {
                AddressFormat::Hex => None,
                AddressFormat::Bech32m => Some(recipient_text.to_owned()),
            },
            amount_atoms: plan.amount_atoms.to_string(),
            fee_atoms: plan.fee_atoms.to_string(),
            change_atoms: plan.change_atoms.to_string(),
            input_atoms: plan.input_atoms.to_string(),
            selected_inputs: plan.selected.len(),
        };
        Ok(Self { plan, summary })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingPaymentState {
    BroadcastUnknown,
    Accepted,
    Confirmed,
    Conflicted,
    Dropped,
}

impl PendingPaymentState {
    fn reserves_inputs(self) -> bool {
        // Every observed state remains reorg-reconcilable. The official API
        // contract does not yet identify a proof-backed terminal state that is
        // safe for releasing an outpoint locally.
        true
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredOutPoint {
    txid: String,
    index: u32,
}

impl From<OutPoint> for StoredOutPoint {
    fn from(value: OutPoint) -> Self {
        Self {
            txid: hex::encode(value.txid),
            index: value.index,
        }
    }
}

impl StoredOutPoint {
    fn decode(&self) -> Result<OutPoint, PaymentStoreError> {
        Ok(OutPoint {
            txid: decode_hex32(&self.txid)?,
            index: self.index,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingPaymentRecord {
    intent: String,
    txid: String,
    recipient: String,
    amount_atoms: String,
    fee_atoms: String,
    change_atoms: String,
    selected: Vec<StoredOutPoint>,
    state: PendingPaymentState,
    confirmations: u64,
    created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPaymentView {
    pub intent: String,
    pub txid: String,
    pub recipient: String,
    pub amount_atoms: String,
    pub fee_atoms: String,
    pub change_atoms: String,
    pub state: PendingPaymentState,
    pub confirmations: u64,
    pub created_at: u64,
}

impl From<&PendingPaymentRecord> for PendingPaymentView {
    fn from(record: &PendingPaymentRecord) -> Self {
        Self {
            intent: record.intent.clone(),
            txid: record.txid.clone(),
            recipient: record.recipient.clone(),
            amount_atoms: record.amount_atoms.clone(),
            fee_atoms: record.fee_atoms.clone(),
            change_atoms: record.change_atoms.clone(),
            state: record.state,
            confirmations: record.confirmations,
            created_at: record.created_at,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingFile {
    version: u32,
    records: Vec<PendingPaymentRecord>,
}

#[derive(Debug)]
pub struct PaymentStore {
    path: PathBuf,
    pending: PendingFile,
    prepared: Option<PreparedPayment>,
}

impl PaymentStore {
    pub fn load(path: PathBuf) -> Result<Self, PaymentStoreError> {
        let pending = if path.exists() {
            let metadata = fs::metadata(&path).map_err(|_| PaymentStoreError::Io)?;
            if !metadata.is_file() || metadata.len() > MAX_PENDING_FILE_BYTES {
                return Err(PaymentStoreError::Invalid);
            }
            let bytes = fs::read(&path).map_err(|_| PaymentStoreError::Io)?;
            serde_json::from_slice(&bytes).map_err(|_| PaymentStoreError::Invalid)?
        } else {
            PendingFile {
                version: 1,
                records: Vec::new(),
            }
        };
        validate_pending_file(&pending)?;
        Ok(Self {
            path,
            pending,
            prepared: None,
        })
    }

    pub fn reserved_inputs(&self) -> Result<HashSet<OutPoint>, PaymentStoreError> {
        self.pending
            .records
            .iter()
            .filter(|record| record.state.reserves_inputs())
            .flat_map(|record| record.selected.iter())
            .map(StoredOutPoint::decode)
            .collect()
    }

    pub fn prepare(
        &mut self,
        payment: PreparedPayment,
    ) -> Result<PaymentSummary, PaymentStoreError> {
        let intent = &payment.summary.intent;
        if self
            .pending
            .records
            .iter()
            .any(|record| &record.intent == intent)
        {
            return Err(PaymentStoreError::Duplicate);
        }
        let reserved = self.reserved_inputs()?;
        if payment
            .plan
            .selected
            .iter()
            .any(|input| reserved.contains(input))
        {
            return Err(PaymentStoreError::Duplicate);
        }
        let summary = payment.summary.clone();
        self.prepared = Some(payment);
        Ok(summary)
    }

    pub fn prepared(&self, intent: &str) -> Result<&PreparedPayment, PaymentStoreError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(PaymentStoreError::ConfirmationMismatch)?;
        if prepared.summary.intent != intent {
            return Err(PaymentStoreError::ConfirmationMismatch);
        }
        Ok(prepared)
    }

    /// Discards a not-yet-signed approval whenever the wallet loses its
    /// authenticated foreground session. Persisted broadcast state is kept.
    pub fn clear_prepared(&mut self) {
        self.prepared = None;
    }

    pub fn record_before_broadcast(
        &mut self,
        intent: &str,
        transaction: &SignedTransaction,
    ) -> Result<PendingPaymentView, PaymentStoreError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(PaymentStoreError::ConfirmationMismatch)?;
        if prepared.summary.intent != intent
            || transaction.signing_digest != prepared.plan.signing_digest()
        {
            return Err(PaymentStoreError::ConfirmationMismatch);
        }
        let record = PendingPaymentRecord {
            intent: intent.to_owned(),
            txid: transaction.txid_hex(),
            recipient: prepared.summary.recipient,
            amount_atoms: prepared.summary.amount_atoms,
            fee_atoms: prepared.summary.fee_atoms,
            change_atoms: prepared.summary.change_atoms,
            selected: prepared.plan.selected.into_iter().map(Into::into).collect(),
            state: PendingPaymentState::BroadcastUnknown,
            confirmations: 0,
            created_at: unix_time(),
        };
        if self
            .pending
            .records
            .iter()
            .any(|existing| existing.intent == record.intent || existing.txid == record.txid)
        {
            return Err(PaymentStoreError::Duplicate);
        }
        self.pending.records.push(record);
        if let Err(error) = self.persist() {
            self.pending.records.pop();
            return Err(error);
        }
        Ok(self.pending.records.last().expect("just inserted").into())
    }

    pub fn update(
        &mut self,
        txid: &str,
        state: PendingPaymentState,
        confirmations: u64,
    ) -> Result<PendingPaymentView, PaymentStoreError> {
        let index = self
            .pending
            .records
            .iter()
            .position(|record| record.txid == txid)
            .ok_or(PaymentStoreError::Invalid)?;
        let previous_state = self.pending.records[index].state;
        let previous_confirmations = self.pending.records[index].confirmations;
        self.pending.records[index].state = state;
        self.pending.records[index].confirmations = confirmations;
        if let Err(error) = self.persist() {
            self.pending.records[index].state = previous_state;
            self.pending.records[index].confirmations = previous_confirmations;
            return Err(error);
        }
        Ok((&self.pending.records[index]).into())
    }

    pub fn views(&self) -> Vec<PendingPaymentView> {
        self.pending.records.iter().rev().map(Into::into).collect()
    }

    pub fn active_txids(&self) -> Vec<String> {
        self.pending
            .records
            .iter()
            .map(|record| record.txid.clone())
            .collect()
    }

    fn persist(&self) -> Result<(), PaymentStoreError> {
        let parent = self.path.parent().ok_or(PaymentStoreError::Io)?;
        fs::create_dir_all(parent).map_err(|_| PaymentStoreError::Io)?;
        let bytes = serde_json::to_vec(&self.pending).map_err(|_| PaymentStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_PENDING_FILE_BYTES {
            return Err(PaymentStoreError::Invalid);
        }
        let mut suffix = [0_u8; 12];
        getrandom::fill(&mut suffix).map_err(|_| PaymentStoreError::Io)?;
        let temporary = parent.join(format!(".pending-{}.tmp", hex::encode(suffix)));
        let result = write_private_file(&temporary, &bytes).and_then(|()| {
            fs::rename(&temporary, &self.path).map_err(|_| PaymentStoreError::Io)?;
            sync_parent_directory(parent)
        });
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), PaymentStoreError> {
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PaymentStoreError::Io)
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<(), PaymentStoreError> {
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), PaymentStoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| PaymentStoreError::Io)?;
    file.write_all(bytes).map_err(|_| PaymentStoreError::Io)?;
    file.sync_all().map_err(|_| PaymentStoreError::Io)
}

fn validate_pending_file(file: &PendingFile) -> Result<(), PaymentStoreError> {
    if file.version != 1 || file.records.len() > 1024 {
        return Err(PaymentStoreError::Invalid);
    }
    let mut intents = HashSet::new();
    let mut txids = HashSet::new();
    for record in &file.records {
        decode_hex32(&record.intent)?;
        decode_hex32(&record.txid)?;
        if record.recipient.len() > 128
            || AddressCodec::mainnet().decode(&record.recipient).is_err()
            || record.selected.is_empty()
            || record.selected.len() > 128
            || record
                .amount_atoms
                .parse::<u64>()
                .ok()
                .filter(|v| *v > 0)
                .is_none()
            || record.fee_atoms.parse::<u64>().is_err()
            || record.change_atoms.parse::<u64>().is_err()
            || !intents.insert(&record.intent)
            || !txids.insert(&record.txid)
        {
            return Err(PaymentStoreError::Invalid);
        }
        for outpoint in &record.selected {
            outpoint.decode()?;
        }
    }
    Ok(())
}

fn decode_hex32(value: &str) -> Result<[u8; 32], PaymentStoreError> {
    let bytes = hex::decode(value).map_err(|_| PaymentStoreError::Invalid)?;
    bytes.try_into().map_err(|_| PaymentStoreError::Invalid)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmfd_wallet_core::{PaymentPlanner, Utxo};

    fn presentation_plan(recipient: &str) -> PaymentPlan {
        let owner: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        PaymentPlanner::mainnet(owner)
            .unwrap()
            .plan(
                recipient,
                10_000_000,
                10_000_000,
                2,
                &[Utxo {
                    outpoint: OutPoint {
                        txid: [0x31; 32],
                        index: 0,
                    },
                    value_atoms: 30_000_000,
                    destination: owner,
                    spendable_height: 1,
                    known_spent: false,
                    locally_reserved: false,
                }],
            )
            .unwrap()
    }

    #[test]
    fn invalid_or_oversized_pending_state_fails_closed() {
        let root = std::env::temp_dir().join(format!("cmfd-payment-store-{}", unix_time()));
        fs::create_dir_all(&root).unwrap();
        let invalid = root.join("invalid.json");
        fs::write(&invalid, br#"{"version":9,"records":[]}"#).unwrap();
        assert!(matches!(
            PaymentStore::load(invalid),
            Err(PaymentStoreError::Invalid)
        ));
        let oversized = root.join("oversized.json");
        fs::write(&oversized, vec![0_u8; MAX_PENDING_FILE_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            PaymentStore::load(oversized),
            Err(PaymentStoreError::Invalid)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hexadecimal_recipient_summary_preserves_the_exact_input() {
        let recipient = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let prepared =
            PreparedPayment::from_recipient(presentation_plan(recipient), recipient).unwrap();

        assert_eq!(prepared.summary.recipient_hex, recipient);
        assert_eq!(prepared.summary.recipient_bech32m, None);
    }

    #[test]
    fn bech32m_recipient_summary_shows_its_hex_identity_and_exact_input() {
        let recipient_key: [u8; 32] =
            hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap()
                .try_into()
                .unwrap();
        let recipient = AddressCodec::mainnet().render(&recipient_key);
        let prepared =
            PreparedPayment::from_recipient(presentation_plan(&recipient), &recipient).unwrap();

        assert_eq!(prepared.summary.recipient_hex, hex::encode(recipient_key));
        assert_eq!(
            prepared.summary.recipient_bech32m.as_deref(),
            Some(recipient.as_str())
        );
    }

    #[test]
    fn recipient_summary_rejects_an_identity_different_from_the_plan() {
        let planned = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let different = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        assert!(matches!(
            PreparedPayment::from_recipient(presentation_plan(planned), different),
            Err(PaymentStoreError::RecipientMismatch)
        ));
    }

    #[test]
    fn ambiguous_payment_survives_restart_and_reserves_its_input() {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let root =
            std::env::temp_dir().join(format!("cmfd-payment-persist-{}", hex::encode(suffix)));
        let path = root.join("pending.json");
        let owner: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let outpoint = OutPoint {
            txid: [7_u8; 32],
            index: 3,
        };
        let plan = PaymentPlanner::mainnet(owner)
            .unwrap()
            .plan(
                &AddressCodec::mainnet().render(&owner),
                10_000_000,
                10_000_000,
                2,
                &[Utxo {
                    outpoint,
                    value_atoms: 30_000_000,
                    destination: owner,
                    spendable_height: 1,
                    known_spent: false,
                    locally_reserved: false,
                }],
            )
            .unwrap();
        let digest = plan.signing_digest();
        let prepared = PreparedPayment::new(plan);
        let intent = prepared.summary.intent.clone();
        let mut store = PaymentStore::load(path.clone()).unwrap();
        store.prepare(prepared).unwrap();
        store
            .record_before_broadcast(
                &intent,
                &SignedTransaction {
                    txid: [8_u8; 32],
                    signing_digest: digest,
                    frame: vec![1, 2, 3],
                },
            )
            .unwrap();
        drop(store);

        let restored = PaymentStore::load(path).unwrap();
        assert_eq!(restored.views().len(), 1);
        assert_eq!(
            restored.views()[0].state,
            PendingPaymentState::BroadcastUnknown
        );
        assert_eq!(
            restored.reserved_inputs().unwrap(),
            HashSet::from([outpoint])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_observed_payment_state_remains_reserved_and_reconcilable() {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).unwrap();
        let root = std::env::temp_dir().join(format!("cmfd-payment-reorg-{}", hex::encode(suffix)));
        let path = root.join("pending.json");
        let owner: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let outpoint = OutPoint {
            txid: [9_u8; 32],
            index: 1,
        };
        let plan = PaymentPlanner::mainnet(owner)
            .unwrap()
            .plan(
                &AddressCodec::mainnet().render(&owner),
                10_000_000,
                10_000_000,
                2,
                &[Utxo {
                    outpoint,
                    value_atoms: 30_000_000,
                    destination: owner,
                    spendable_height: 1,
                    known_spent: false,
                    locally_reserved: false,
                }],
            )
            .unwrap();
        let digest = plan.signing_digest();
        let prepared = PreparedPayment::new(plan);
        let intent = prepared.summary.intent.clone();
        let txid = hex::encode([10_u8; 32]);
        let mut store = PaymentStore::load(path).unwrap();
        store.prepare(prepared).unwrap();
        store
            .record_before_broadcast(
                &intent,
                &SignedTransaction {
                    txid: [10_u8; 32],
                    signing_digest: digest,
                    frame: vec![4, 5, 6],
                },
            )
            .unwrap();
        store
            .update(&txid, PendingPaymentState::Confirmed, 3)
            .unwrap();
        assert_eq!(store.reserved_inputs().unwrap(), HashSet::from([outpoint]));
        assert_eq!(store.active_txids(), vec![txid.clone()]);

        for state in [
            PendingPaymentState::Accepted,
            PendingPaymentState::Conflicted,
            PendingPaymentState::Dropped,
        ] {
            store.update(&txid, state, 0).unwrap();
            assert_eq!(store.reserved_inputs().unwrap(), HashSet::from([outpoint]));
            assert_eq!(store.active_txids(), vec![txid.clone()]);
        }

        fs::remove_dir_all(root).unwrap();
    }
}
