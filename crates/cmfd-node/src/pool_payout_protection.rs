//! Pool-owned payout holds. No client message can clear these holds or change
//! credits. Operator reconciliation runs offline under the node/ledger locks.

use super::*;

const MAX_INCIDENTS: usize = 4096;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectionState {
    incidents: Vec<Incident>,
}

impl ProtectionState {
    pub(super) fn is_empty(&self) -> bool {
        self.incidents.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    RewardBackingLost,
    MissingPayoutFunding,
    FundingShortfall,
    LegacyPaymentUncertain,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Incident {
    id: u64,
    reason: Reason,
    block_id: Option<[u8; 32]>,
    payout_txid: Option<[u8; 32]>,
    tip: [u8; 32],
    height: u64,
    detected_at: u64,
    resolution: Option<Resolution>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    tip: [u8; 32],
    height: u64,
    at: u64,
    prior_generation: u64,
    mature_assets: u64,
    required_assets: u64,
    operator_note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolPayoutProtectionSnapshot {
    pub requires_reconciliation: bool,
    pub all_payouts_paused: bool,
    pub affected_payouts: Vec<String>,
    pub unresolved_incidents: Vec<PoolPayoutIncidentView>,
    pub resolved_incidents: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolPayoutIncidentView {
    pub id: u64,
    pub reason: String,
    pub block_id: Option<String>,
    pub payout_txid: Option<String>,
    pub detected_tip: String,
    pub detected_height: u64,
}

#[derive(Debug, Serialize)]
pub struct PoolPayoutProtectionReport {
    pub schema: &'static str,
    pub network_id: String,
    pub chain_tip: String,
    pub height: u64,
    pub ledger_generation: u64,
    pub protection: PoolPayoutProtectionSnapshot,
    pub mature_wallet_assets_atoms: String,
    pub outstanding_credit_atoms: String,
    pub fee_reserve_atoms: String,
    pub funding_shortfall_atoms: String,
    pub automatic_payout_fee_atoms: String,
    pub blocking_signed_transactions: Vec<String>,
    pub legacy_abandoned_transactions_require_review: bool,
}

pub struct PoolPayoutReconciliationRequest {
    pub expected_tip: [u8; 32],
    pub expected_ledger_generation: u64,
    pub fee_atoms: u64,
    pub operator_note: String,
}

#[derive(Default)]
pub(super) struct Holds {
    pub all: bool,
    affected: HashSet<[u8; 32]>,
}

impl Holds {
    pub(super) fn blocks(&self, payout: [u8; 32]) -> bool {
        self.all || self.affected.contains(&payout)
    }
}

/// Whether any incident, resolved or not, still refers to this block. Such
/// blocks stay in the live ledger because `validate` checks the reference.
pub(super) fn references_block(ledger: &Ledger, block_id: [u8; 32]) -> bool {
    ledger
        .payout_protection
        .incidents
        .iter()
        .any(|incident| incident.block_id == Some(block_id))
}

pub(super) fn references_payout_transaction(ledger: &Ledger, txid: [u8; 32]) -> bool {
    ledger
        .payout_protection
        .incidents
        .iter()
        .any(|incident| incident.payout_txid == Some(txid))
}

pub(super) fn holds(ledger: &Ledger) -> Holds {
    let mut result = Holds::default();
    for incident in ledger
        .payout_protection
        .incidents
        .iter()
        .filter(|i| i.resolution.is_none())
    {
        match incident.reason {
            Reason::FundingShortfall => result.all = true,
            Reason::RewardBackingLost => {
                if let Some(block) = incident
                    .block_id
                    .and_then(|id| ledger.pplns_blocks.get(&id))
                {
                    result
                        .affected
                        .extend(block.allocations.iter().map(|a| a.payout));
                }
            }
            Reason::MissingPayoutFunding | Reason::LegacyPaymentUncertain => {
                if let Some(record) = incident
                    .payout_txid
                    .and_then(|id| ledger.payout_transactions.get(&id))
                {
                    result.affected.insert(record.payout);
                }
            }
        }
    }
    result
}

pub(super) fn snapshot(ledger: &Ledger) -> PoolPayoutProtectionSnapshot {
    let held = holds(ledger);
    let mut affected: Vec<_> = held.affected.into_iter().map(hex::encode).collect();
    affected.sort();
    let unresolved: Vec<_> = ledger
        .payout_protection
        .incidents
        .iter()
        .filter(|i| i.resolution.is_none())
        .map(|incident| PoolPayoutIncidentView {
            id: incident.id,
            reason: match incident.reason {
                Reason::RewardBackingLost => "reward_backing_lost",
                Reason::MissingPayoutFunding => "missing_payout_funding",
                Reason::FundingShortfall => "funding_shortfall",
                Reason::LegacyPaymentUncertain => "legacy_payment_uncertain",
            }
            .into(),
            block_id: incident.block_id.map(hex::encode),
            payout_txid: incident.payout_txid.map(hex::encode),
            detected_tip: hex::encode(incident.tip),
            detected_height: incident.height,
        })
        .collect();
    PoolPayoutProtectionSnapshot {
        requires_reconciliation: !unresolved.is_empty(),
        all_payouts_paused: held.all,
        affected_payouts: affected,
        resolved_incidents: ledger.payout_protection.incidents.len() - unresolved.len(),
        unresolved_incidents: unresolved,
    }
}

fn add_incident(
    ledger: &mut Ledger,
    node: &Node,
    reason: Reason,
    block_id: Option<[u8; 32]>,
    payout_txid: Option<[u8; 32]>,
) -> Result<(), PoolError> {
    if ledger.payout_protection.incidents.iter().any(|i| {
        i.resolution.is_none()
            && i.reason == reason
            && i.block_id == block_id
            && i.payout_txid == payout_txid
    }) {
        return Ok(());
    }
    if ledger.payout_protection.incidents.len() >= MAX_INCIDENTS {
        return Err(PoolError::LedgerCapacity);
    }
    let id = ledger.payout_protection.incidents.len() as u64 + 1;
    ledger.payout_protection.incidents.push(Incident {
        id,
        reason,
        block_id,
        payout_txid,
        tip: node.state.tip(),
        height: node.state.next_height().saturating_sub(1),
        detected_at: unix_time_seconds()?,
        resolution: None,
    });
    Ok(())
}

pub(super) fn backing_changed(
    ledger: &Ledger,
    block_id: [u8; 32],
    state: PoolBlockState,
    confirmations: u64,
) -> bool {
    let Some(record) = ledger.pplns_blocks.get(&block_id).filter(|r| r.distributed) else {
        return false;
    };
    let mature = state == PoolBlockState::Canonical && confirmations >= COINBASE_MATURITY;
    (!mature && record.last_backing_mature != Some(false))
        || (mature && record.last_backing_mature == Some(false))
}

pub(super) fn observe_backing(
    ledger: &mut Ledger,
    node: &Node,
    block_id: [u8; 32],
) -> Result<(), PoolError> {
    let Some(record) = ledger.pplns_blocks.get(&block_id).filter(|r| r.distributed) else {
        return Ok(());
    };
    let block = &ledger.blocks[&block_id];
    let mature =
        block.state == PoolBlockState::Canonical && block.confirmations >= COINBASE_MATURITY;
    let previous = record.last_backing_mature;
    if !mature && previous != Some(false) {
        add_incident(
            ledger,
            node,
            Reason::RewardBackingLost,
            Some(block_id),
            None,
        )?;
    }
    if !mature || previous.is_some() {
        ledger
            .pplns_blocks
            .get_mut(&block_id)
            .unwrap()
            .last_backing_mature = Some(mature);
    }
    Ok(())
}

pub(super) fn missing_funding(
    ledger: &DurableLedger,
    node: &Node,
    txid: [u8; 32],
) -> Result<(), PoolError> {
    ledger.transaction(|state| {
        add_incident(state, node, Reason::MissingPayoutFunding, None, Some(txid))
    })
}

struct Coverage {
    assets: u64,
    outstanding: u64,
    fees: u64,
    required: u64,
}

fn coverage(node: &Node, ledger: &Ledger, fee_atoms: u64) -> Result<Coverage, PoolError> {
    let mut unavailable = node
        .exchange_withdrawal_reservations
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    // Do not count coins reserved by unrelated/manual mempool transactions.
    // Tracked pool payments remain liabilities until confirmation, so their
    // still-unspent inputs count as assets and their fees are reserved below.
    for (txid, entry) in &node.mempool {
        if !ledger.payout_transactions.contains_key(txid) {
            unavailable.extend(entry.transaction.inputs.iter().map(|i| i.previous));
        }
    }
    let owner = node.wallet_destination();
    let assets = node
        .state
        .utxos()
        .iter()
        .filter(|(outpoint, output)| {
            output.lock == OutputLock::Key(owner)
                && output.spendable_height <= node.state.next_height()
                && !unavailable.contains(outpoint)
        })
        .try_fold(0u64, |sum, (_, output)| {
            checked_ledger_add(sum, output.value, "pool mature assets")
        })?;
    let totals = payout_transaction_totals(ledger)?;
    let mut outstanding = 0u64;
    let mut fees = 0u64;
    for (payout, record) in &ledger.payouts {
        let (reserved, confirmed) = totals.get(payout).copied().unwrap_or_default();
        outstanding = checked_ledger_add(
            outstanding,
            record
                .credited_devnet_atoms
                .checked_sub(confirmed)
                .ok_or_else(|| {
                    PoolError::LedgerCorrupt("confirmed payments exceed credits".into())
                })?,
            "pool outstanding credit",
        )?;
        if record.credited_devnet_atoms > reserved {
            fees = checked_ledger_add(fees, fee_atoms, "pool payout fee reserve")?;
        }
    }
    for record in ledger.payout_transactions.values() {
        if matches!(
            record.state,
            PoolPayoutTransactionState::Prepared | PoolPayoutTransactionState::Broadcast
        ) {
            fees = checked_ledger_add(fees, record.fee_atoms, "pending pool fees")?;
        }
    }
    let required = checked_ledger_add(outstanding, fees, "required pool funding")?;
    Ok(Coverage {
        assets,
        outstanding,
        fees,
        required,
    })
}

pub(super) fn check_funding(
    ledger: &DurableLedger,
    node: &Node,
    fee_atoms: u64,
) -> Result<(), PoolError> {
    let must_hold = {
        let state = ledger
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        if state.payout_protection.is_empty()
            || state
                .payout_protection
                .incidents
                .iter()
                .any(|i| i.reason == Reason::FundingShortfall && i.resolution.is_none())
        {
            return Ok(());
        }
        let funds = coverage(node, &state, fee_atoms)?;
        funds.assets < funds.required
    };
    if must_hold {
        ledger
            .transaction(|state| add_incident(state, node, Reason::FundingShortfall, None, None))?;
    }
    Ok(())
}

pub(super) fn refresh_payment_states(
    ledger: &DurableLedger,
    node: &mut Node,
) -> Result<(), PoolError> {
    let records: Vec<_> = ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?
        .payout_transactions
        .iter()
        .map(|(id, r)| (*id, r.clone()))
        .collect();
    let ids = records.iter().map(|(id, _)| *id).collect();
    let confirmed = node.active_transaction_confirmations_for(&ids)?;
    let updates: Vec<_> = records
        .into_iter()
        .filter_map(|(id, record)| {
            let (state, confirmations) = if let Some(count) = confirmed.get(&id) {
                (PoolPayoutTransactionState::Confirmed, *count)
            } else if node.mempool_contains_transaction(id) {
                (PoolPayoutTransactionState::Broadcast, 0)
            } else if record.state == PoolPayoutTransactionState::Abandoned {
                (PoolPayoutTransactionState::Abandoned, 0)
            } else {
                (PoolPayoutTransactionState::Prepared, 0)
            };
            (state != record.state || confirmations != record.confirmations).then_some((
                id,
                state,
                confirmations,
            ))
        })
        .collect();
    let hazards = {
        let state = ledger
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?;
        state
            .payout_transactions
            .iter()
            .filter_map(|(id, record)| {
                let status = updates
                    .iter()
                    .find(|(updated, _, _)| updated == id)
                    .map_or(record.state, |(_, status, _)| *status);
                let reason = if status == PoolPayoutTransactionState::Abandoned {
                    Reason::LegacyPaymentUncertain
                } else if matches!(
                    status,
                    PoolPayoutTransactionState::Prepared | PoolPayoutTransactionState::Broadcast
                ) && node
                    .state
                    .validate_transactions_for_next_block(std::slice::from_ref(&record.transaction))
                    .is_err()
                {
                    Reason::MissingPayoutFunding
                } else {
                    return None;
                };
                (!state.payout_protection.incidents.iter().any(|incident| {
                    incident.reason == reason
                        && incident.payout_txid == Some(*id)
                        && incident.resolution.is_none()
                }))
                .then_some((*id, reason))
            })
            .collect::<Vec<_>>()
    };
    if !updates.is_empty() || !hazards.is_empty() {
        ledger.transaction(|state| {
            for (id, status, confirmations) in updates {
                let record = state.payout_transactions.get_mut(&id).unwrap();
                record.state = status;
                record.confirmations = confirmations;
            }
            for (id, reason) in hazards {
                add_incident(state, node, reason, None, Some(id))?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn blocking_signed_transactions(node: &Node, ledger: &Ledger) -> Vec<String> {
    let mut input_counts = HashMap::new();
    for record in ledger.payout_transactions.values().filter(|r| {
        matches!(
            r.state,
            PoolPayoutTransactionState::Prepared | PoolPayoutTransactionState::Broadcast
        )
    }) {
        for input in &record.transaction.inputs {
            *input_counts.entry(input.previous).or_insert(0usize) += 1;
        }
    }
    ledger
        .payout_transactions
        .iter()
        .filter_map(|(id, record)| {
            if !matches!(
                record.state,
                PoolPayoutTransactionState::Prepared | PoolPayoutTransactionState::Broadcast
            ) {
                return None;
            }
            let invalid = node
                .state
                .validate_transactions_for_next_block(std::slice::from_ref(&record.transaction))
                .is_err();
            let conflicts = record
                .transaction
                .inputs
                .iter()
                .any(|input| input_counts[&input.previous] > 1)
                || node.mempool.iter().any(|(other_id, entry)| {
                    other_id != id
                        && entry.transaction.inputs.iter().any(|input| {
                            record
                                .transaction
                                .inputs
                                .iter()
                                .any(|pending| pending.previous == input.previous)
                        })
                });
            (invalid || conflicts).then(|| hex::encode(id))
        })
        .collect()
}

fn report(
    node: &Node,
    ledger: &DurableLedger,
    fee_atoms: u64,
) -> Result<PoolPayoutProtectionReport, PoolError> {
    let state = ledger
        .state
        .lock()
        .map_err(|_| PoolError::SharedStatePoisoned)?;
    let funds = coverage(node, &state, fee_atoms)?;
    Ok(PoolPayoutProtectionReport {
        schema: "CommonFoundry/PoolPayoutProtection/v1",
        network_id: hex::encode(node.params.network_id),
        chain_tip: hex::encode(node.state.tip()),
        height: node.state.next_height().saturating_sub(1),
        ledger_generation: state.generation,
        protection: snapshot(&state),
        mature_wallet_assets_atoms: funds.assets.to_string(),
        outstanding_credit_atoms: funds.outstanding.to_string(),
        fee_reserve_atoms: funds.fees.to_string(),
        funding_shortfall_atoms: funds.required.saturating_sub(funds.assets).to_string(),
        automatic_payout_fee_atoms: fee_atoms.to_string(),
        blocking_signed_transactions: blocking_signed_transactions(node, &state),
        legacy_abandoned_transactions_require_review: state
            .payout_transactions
            .values()
            .any(|r| r.state == PoolPayoutTransactionState::Abandoned),
    })
}

/// Preflight before opening a node, so a mistyped maintenance path cannot
/// initialize a new wallet and empty accounting ledger.
pub fn require_existing_pool_ledger(data_dir: &Path) -> Result<(), PoolError> {
    let directory = data_dir.join("pool-ledger");
    if !(0..=1).any(|slot| {
        directory
            .join(format!("{POOL_LEDGER_FILE_PREFIX}.{slot}.json"))
            .is_file()
            || directory
                .join(format!("{LEGACY_POOL_LEDGER_FILE_PREFIX}.{slot}.json"))
                .is_file()
    }) {
        return Err(PoolError::Reconciliation(
            "existing pool ledger not found".into(),
        ));
    }
    Ok(())
}

fn open_operator_ledger(node: &Node, fee_atoms: u64) -> Result<DurableLedger, PoolError> {
    if fee_atoms == 0
        || fee_atoms < cmfd_consensus::economics::minimum_transaction_fee(node.params.network_id)
    {
        return Err(PoolError::InvalidPayoutPolicy);
    }
    require_existing_pool_ledger(&node.data_dir)?;
    DurableLedger::open(
        Some(node.data_dir.join("pool-ledger")),
        node.params.network_id,
        node.fingerprint,
    )
}

/// Offline operator inspection: records discovered holds/status changes, but
/// never signs, submits, replaces or rebroadcasts a payment.
pub fn inspect_pool_payout_protection(
    node: &mut Node,
    fee_atoms: u64,
) -> Result<PoolPayoutProtectionReport, PoolError> {
    let ledger = open_operator_ledger(node, fee_atoms)?;
    reconcile_pool_blocks_for_node(&ledger, node, true)?;
    refresh_payment_states(&ledger, node)?;
    check_funding(&ledger, node, fee_atoms)?;
    report(node, &ledger, fee_atoms)
}

/// Resolve the currently reported holds only when all credits/fees are backed
/// and existing signed payments remain valid. This never creates replacement
/// payments or erases credit/reservation history.
pub fn reconcile_pool_payout_protection(
    node: &mut Node,
    request: PoolPayoutReconciliationRequest,
) -> Result<PoolPayoutProtectionReport, PoolError> {
    if request.operator_note.trim().is_empty()
        || request.operator_note.len() > 256
        || request.operator_note.chars().any(char::is_control)
    {
        return Err(PoolError::Reconciliation(
            "supply a nonempty operator note of at most 256 bytes, without control characters"
                .into(),
        ));
    }
    let ledger = open_operator_ledger(node, request.fee_atoms)?;
    if node.state.tip() != request.expected_tip
        || ledger
            .state
            .lock()
            .map_err(|_| PoolError::SharedStatePoisoned)?
            .generation
            != request.expected_ledger_generation
    {
        return Err(PoolError::Reconciliation(
            "chain tip or ledger generation changed; inspect again".into(),
        ));
    }
    reconcile_pool_blocks_for_node(&ledger, node, true)?;
    refresh_payment_states(&ledger, node)?;
    check_funding(&ledger, node, request.fee_atoms)?;
    let before = report(node, &ledger, request.fee_atoms)?;
    if before.ledger_generation != request.expected_ledger_generation {
        return Err(PoolError::Reconciliation(
            "new accounting changes were detected; inspect again".into(),
        ));
    }
    if !before.protection.requires_reconciliation {
        return Err(PoolError::Reconciliation(
            "no unresolved payout holds".into(),
        ));
    }
    if !before.blocking_signed_transactions.is_empty()
        || before.legacy_abandoned_transactions_require_review
    {
        return Err(PoolError::Reconciliation("unresolved or legacy-retired signed payments require manual review; reservations were not released".into()));
    }
    ledger.transaction(|state| {
        let funds = coverage(node, state, request.fee_atoms)?;
        if funds.assets < funds.required {
            return Err(PoolError::Reconciliation(
                "mature wallet funds do not cover all outstanding credits and fees".into(),
            ));
        }
        let resolution = Resolution {
            tip: node.state.tip(),
            height: node.state.next_height().saturating_sub(1),
            at: unix_time_seconds()?,
            prior_generation: state.generation,
            mature_assets: funds.assets,
            required_assets: funds.required,
            operator_note: request.operator_note,
        };
        for incident in &mut state.payout_protection.incidents {
            if incident.resolution.is_none() {
                incident.resolution = Some(resolution.clone());
            }
        }
        Ok(())
    })?;
    report(node, &ledger, request.fee_atoms)
}

pub(super) fn validate(ledger: &Ledger) -> Result<(), PoolError> {
    if ledger.payout_protection.incidents.len() > MAX_INCIDENTS {
        return Err(PoolError::LedgerCapacity);
    }
    let mut unresolved = HashSet::new();
    for (index, incident) in ledger.payout_protection.incidents.iter().enumerate() {
        let valid_reference = match incident.reason {
            Reason::RewardBackingLost => {
                incident.payout_txid.is_none()
                    && incident.block_id.is_some_and(|id| {
                        ledger.pplns_blocks.get(&id).is_some_and(|r| r.distributed)
                    })
            }
            Reason::MissingPayoutFunding | Reason::LegacyPaymentUncertain => {
                incident.block_id.is_none()
                    && incident
                        .payout_txid
                        .is_some_and(|id| ledger.payout_transactions.contains_key(&id))
            }
            Reason::FundingShortfall => {
                incident.block_id.is_none() && incident.payout_txid.is_none()
            }
        };
        if incident.id != index as u64 + 1
            || !valid_reference
            || incident.tip == [0; 32]
            || incident.detected_at == 0
            || (incident.resolution.is_none()
                && !unresolved.insert((
                    incident.reason as u8,
                    incident.block_id,
                    incident.payout_txid,
                )))
        {
            return Err(PoolError::LedgerCorrupt(
                "invalid payout protection incident".into(),
            ));
        }
        if let Some(resolution) = &incident.resolution
            && (resolution.tip == [0; 32]
                || resolution.prior_generation >= ledger.generation
                || resolution.mature_assets < resolution.required_assets
                || resolution.operator_note.trim().is_empty()
                || resolution.operator_note.len() > 256
                || resolution.operator_note.chars().any(char::is_control))
        {
            return Err(PoolError::LedgerCorrupt(
                "invalid payout reconciliation receipt".into(),
            ));
        }
    }
    for (id, record) in &ledger.pplns_blocks {
        if record.last_backing_mature.is_some()
            && (!record.distributed
                || !ledger.payout_protection.incidents.iter().any(|incident| {
                    incident.reason == Reason::RewardBackingLost && incident.block_id == Some(*id)
                }))
        {
            return Err(PoolError::LedgerCorrupt(
                "payout backing observation lacks a distributed reward incident".into(),
            ));
        }
    }
    Ok(())
}
