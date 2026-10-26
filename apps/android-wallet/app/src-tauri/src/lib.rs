use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use cmfd_wallet_api::{
    AddressHistoryEntry, ApiClient, ApiError, ApiTransactionOutput, ApiUtxo, IndependentUtxo,
    IndependentUtxoClient, UtxoPage,
};
use cmfd_wallet_core::{OutPoint, PaymentPlanner, Utxo, parse_cmfd};
use cmfd_wallet_engine::{EngineStatus, WalletEngine};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_cmfd_android::CmfdAndroidExt;
use zeroize::Zeroizing;

mod payments;

use payments::{
    PaymentStore, PaymentSummary, PendingPaymentState, PendingPaymentView, PreparedPayment,
};

struct WalletState {
    engine: Mutex<WalletEngine>,
    foreground: AtomicBool,
    lifecycle_epoch: AtomicU64,
}

struct PaymentState {
    store: Mutex<PaymentStore>,
    foreground: AtomicBool,
    lifecycle_epoch: AtomicU64,
}

struct WalletGuard<'a> {
    engine: MutexGuard<'a, WalletEngine>,
    foreground: &'a AtomicBool,
    lifecycle_epoch: &'a AtomicU64,
    acquired_epoch: u64,
}

impl Deref for WalletGuard<'_> {
    type Target = WalletEngine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl DerefMut for WalletGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.engine
    }
}

impl Drop for WalletGuard<'_> {
    fn drop(&mut self) {
        if !self.foreground.load(Ordering::Acquire)
            || self.lifecycle_epoch.load(Ordering::Acquire) != self.acquired_epoch
        {
            self.engine.abort_external_operation();
        }
    }
}

impl WalletGuard<'_> {
    fn acknowledge_external_activity_return(&mut self) {
        self.foreground.store(true, Ordering::Release);
        self.acquired_epoch = self.lifecycle_epoch.load(Ordering::Acquire);
    }
}

struct PaymentGuard<'a> {
    store: MutexGuard<'a, PaymentStore>,
    foreground: &'a AtomicBool,
    lifecycle_epoch: &'a AtomicU64,
    acquired_epoch: u64,
}

impl Deref for PaymentGuard<'_> {
    type Target = PaymentStore;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

impl DerefMut for PaymentGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

impl Drop for PaymentGuard<'_> {
    fn drop(&mut self) {
        if !self.foreground.load(Ordering::Acquire)
            || self.lifecycle_epoch.load(Ordering::Acquire) != self.acquired_epoch
        {
            self.store.clear_prepared();
        }
    }
}

impl WalletState {
    fn new(engine: WalletEngine) -> Self {
        Self {
            engine: Mutex::new(engine),
            foreground: AtomicBool::new(true),
            lifecycle_epoch: AtomicU64::new(0),
        }
    }

    fn set_foreground(&self, foreground: bool) {
        if foreground {
            self.foreground.store(true, Ordering::Release);
        } else {
            self.foreground.store(false, Ordering::Release);
            self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
            if let Ok(mut engine) = self.engine.try_lock() {
                engine.abort_external_operation();
            }
        }
    }
}

impl PaymentState {
    fn new(store: PaymentStore) -> Self {
        Self {
            store: Mutex::new(store),
            foreground: AtomicBool::new(true),
            lifecycle_epoch: AtomicU64::new(0),
        }
    }

    fn set_foreground(&self, foreground: bool) {
        if foreground {
            self.foreground.store(true, Ordering::Release);
        } else {
            self.foreground.store(false, Ordering::Release);
            self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
            if let Ok(mut store) = self.store.try_lock() {
                store.clear_prepared();
            }
        }
    }
}

const MAINNET_MINIMUM_FEE_ATOMS: u64 = 10_000_000;
const MAX_UTXO_PAGES: usize = 64;
const MAX_UTXOS: usize = 8_192;
const INPUT_LOOKUP_CONCURRENCY: usize = 8;
const INPUT_VERIFICATION_ERROR: &str = "Les valeurs des entrées ne correspondent pas aux transactions confirmées. L’envoi est bloqué; réessayez après synchronisation du service.";
const INDEPENDENT_VERIFICATION_ERROR: &str = "Le nœud de vérification indépendant est indisponible ou ne confirme pas les entrées sélectionnées. L’envoi est bloqué.";
const MAX_INDEPENDENT_NODE_LAG_BLOCKS: u64 = 6;
/// The wallet gateway proposes inputs. A separate Falkenstein node must agree
/// on every selected outpoint before signing; both are still trusted services.
const TRUST_OFFICIAL_WALLET_GATEWAY_UTXOS: bool = true;
const OFFICIAL_GATEWAY_TRUST_MESSAGE: &str = "Chaque entrée de la passerelle officielle est vérifiée avant signature auprès d’un nœud Falkenstein distinct. Une divergence ou une indisponibilité bloque l’envoi. Le téléphone ne valide pas lui-même toute la chaîne; une compromission des deux services pourrait encore fausser les frais.";
const DEVELOPMENT_BUILD_SEND_MESSAGE: &str = "L’envoi mainnet est désactivé dans les versions de développement débogables. Utilisez une version release signée et validée.";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicWalletStatus {
    configured: bool,
    unlocked: bool,
    recovery_required: bool,
    network_name: &'static str,
    network_id_hex: String,
    destination_hex: Option<String>,
    address: Option<String>,
}

impl PublicWalletStatus {
    fn from_engine(status: EngineStatus, recovery_required: bool) -> Self {
        Self {
            configured: status.configured,
            unlocked: status.unlocked,
            recovery_required,
            network_name: status.network_name,
            network_id_hex: status.network_id_hex,
            destination_hex: status.destination_hex,
            address: status.address,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicHistoryEntry {
    kind: String,
    txid: String,
    block_height: u64,
    block_id: String,
    timestamp: Option<u64>,
    confirmations: u64,
    received_atoms: String,
}

impl From<AddressHistoryEntry> for PublicHistoryEntry {
    fn from(entry: AddressHistoryEntry) -> Self {
        Self {
            kind: entry.kind,
            txid: entry.txid,
            block_height: entry.block_height,
            block_id: entry.block_id,
            timestamp: entry.timestamp,
            confirmations: entry.confirmations,
            received_atoms: entry.received_atoms,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletOverview {
    confirmed_atoms: String,
    spendable_atoms: String,
    immature_atoms: String,
    accepted_height: u64,
    validated_height: Option<u64>,
    includes_mempool: bool,
    has_more_history: bool,
    history: Vec<PublicHistoryEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendAvailability {
    available: bool,
    message: Option<String>,
    next_height: Option<u64>,
    utxo_count: usize,
    spendable_atoms: Option<String>,
    fee_atoms: Option<String>,
    maximum_atoms: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BroadcastOutcome {
    payment: PendingPaymentView,
    submitted: bool,
    message: String,
}

#[tauri::command]
fn wallet_status(
    app: AppHandle,
    state: State<'_, WalletState>,
) -> Result<PublicWalletStatus, String> {
    #[cfg(mobile)]
    {
        let local = app
            .cmfd_android()
            .local_status()
            .map_err(|_| secure_storage_unavailable())?;
        return with_engine_status(&state, local.exists && !local.accessible, |engine| {
            engine.external_status(local.exists)
        });
    }

    #[cfg(desktop)]
    {
        let _ = app;
        with_engine_status(&state, false, |engine| engine.status())
    }
}

#[tauri::command]
fn create_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let configured = app
        .cmfd_android()
        .local_status()
        .map_err(|_| secure_storage_unavailable())?
        .exists;
    let mut engine = lock_engine(&state)?;
    let prepared = engine
        .prepare_external_create(passphrase.as_bytes(), configured)
        .map_err(|_| wallet_operation_failed())?;

    let save_result = app.cmfd_android().save_document(
        prepared.recovery_backup_bytes(),
        "common-foundry-wallet.cmfd-wallet",
    );
    document_picker_returned(&app, &state);
    engine.acknowledge_external_activity_return();
    if save_result.is_err() {
        engine.abort_external_operation();
        return Err(
            "Création annulée: aucune clé locale n’a été activée sans sauvegarde vérifiée."
                .to_owned(),
        );
    }

    if app
        .cmfd_android()
        .store_local(prepared.live_key_bytes())
        .is_err()
    {
        engine.abort_external_operation();
        return Err("La sauvegarde a été créée, mais l’activation locale a échoué. Conservez la sauvegarde et utilisez Restaurer.".to_owned());
    }
    engine
        .external_status(true)
        .map(|status| PublicWalletStatus::from_engine(status, false))
        .map_err(|_| wallet_operation_failed())
}

#[tauri::command]
fn restore_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let local = app
        .cmfd_android()
        .local_status()
        .map_err(|_| secure_storage_unavailable())?;
    if local.exists && local.accessible {
        return Err(
            "Un portefeuille accessible existe déjà; aucune donnée n’a été remplacée.".to_owned(),
        );
    }
    let recovery_result = app.cmfd_android().open_document();
    document_picker_returned(&app, &state);
    let recovery =
        recovery_result.map_err(|_| "Restauration annulée ou sauvegarde illisible.".to_owned())?;
    let mut engine = lock_engine(&state)?;
    let live_key = engine
        .prepare_external_restore(&recovery, passphrase.as_bytes(), false)
        .map_err(|_| "La sauvegarde, le réseau ou la phrase secrète est invalide.".to_owned())?;
    let store_result = if local.exists {
        app.cmfd_android().replace_inaccessible_local(&live_key)
    } else {
        app.cmfd_android().store_local(&live_key)
    };
    if store_result.is_err() {
        engine.abort_external_operation();
        return Err(
            "La sauvegarde est valide, mais Android Keystore n’a pas pu activer le portefeuille."
                .to_owned(),
        );
    }
    engine
        .external_status(true)
        .map(|status| PublicWalletStatus::from_engine(status, false))
        .map_err(|_| wallet_operation_failed())
}

#[tauri::command]
fn unlock_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    passphrase: String,
) -> Result<PublicWalletStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let status = app
        .cmfd_android()
        .local_status()
        .map_err(|_| secure_storage_unavailable())?;
    if !status.exists {
        return Err("Aucun portefeuille local n’est configuré.".to_owned());
    }
    let encrypted = app.cmfd_android().load_local().map_err(|_| {
        "La clé Android Keystore est inaccessible ou les données locales sont endommagées. Restaurez votre sauvegarde officielle."
            .to_owned()
    })?;
    with_engine_status(&state, false, |engine| {
        engine.unlock_external(&encrypted, passphrase.as_bytes())
    })
}

#[tauri::command]
fn lock_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    payments: State<'_, PaymentState>,
) -> Result<PublicWalletStatus, String> {
    lock_payments(&payments)?.clear_prepared();
    let local = app
        .cmfd_android()
        .local_status()
        .map_err(|_| secure_storage_unavailable())?;
    with_engine_status(&state, local.exists && !local.accessible, |engine| {
        engine.lock_external(local.exists)
    })
}

#[tauri::command]
fn export_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    passphrase: String,
) -> Result<(), String> {
    let passphrase = Zeroizing::new(passphrase);
    let local_live_key = app.cmfd_android().load_local().map_err(|_| {
        "La clé Android Keystore est inaccessible; aucune sauvegarde n’a été exportée.".to_owned()
    })?;
    let encrypted = {
        let engine = lock_engine(&state)?;
        engine
            .export_external_authenticated(&local_live_key, passphrase.as_bytes())
            .map_err(|_| {
                "Le portefeuille doit être déverrouillé et la phrase secrète doit être valide."
                    .to_owned()
            })?
    };
    let save_result = app
        .cmfd_android()
        .save_document(&encrypted, "common-foundry-wallet-export.cmfd-wallet");
    document_picker_returned(&app, &state);
    save_result
        .map(|_| ())
        .map_err(|_| "Exportation annulée ou impossible à vérifier.".to_owned())
}

#[tauri::command]
async fn wallet_overview(
    state: State<'_, WalletState>,
    api: State<'_, ApiClient>,
) -> Result<WalletOverview, String> {
    let destination = unlocked_destination(&state)?;
    let snapshot = api.address(&destination).await.map_err(public_api_error)?;
    Ok(WalletOverview {
        confirmed_atoms: snapshot.confirmed_atoms,
        spendable_atoms: snapshot.spendable_atoms,
        immature_atoms: snapshot.immature_atoms,
        accepted_height: snapshot.accepted_height,
        validated_height: snapshot.validated_height,
        includes_mempool: snapshot.includes_mempool,
        has_more_history: snapshot.has_more,
        history: snapshot.history.into_iter().map(Into::into).collect(),
    })
}

#[tauri::command]
async fn send_availability(
    state: State<'_, WalletState>,
    payments: State<'_, PaymentState>,
    api: State<'_, ApiClient>,
    independent: State<'_, IndependentUtxoClient>,
) -> Result<SendAvailability, String> {
    let destination = unlocked_destination(&state)?;
    if !mainnet_send_enabled() {
        return Ok(SendAvailability {
            available: false,
            message: Some(DEVELOPMENT_BUILD_SEND_MESSAGE.to_owned()),
            next_height: None,
            utxo_count: 0,
            spendable_atoms: None,
            fee_atoms: None,
            maximum_atoms: None,
        });
    }
    if independent.probe().await.is_err() {
        return Ok(SendAvailability {
            available: false,
            message: Some(INDEPENDENT_VERIFICATION_ERROR.to_owned()),
            next_height: None,
            utxo_count: 0,
            spendable_atoms: None,
            fee_atoms: None,
            maximum_atoms: None,
        });
    }
    let first_page = match api.utxos(&destination, None).await {
        Ok(page) => page,
        Err(ApiError::Http { code, .. }) if code == "work_check_pending" => {
            return Ok(SendAvailability {
                available: false,
                message: Some("Le serveur valide encore les blocs nécessaires. L’envoi demeure verrouillé pour éviter de dépenser des UTXO non vérifiés.".to_owned()),
                next_height: None,
                utxo_count: 0,
                spendable_atoms: None,
                fee_atoms: None,
                maximum_atoms: None,
            });
        }
        Err(error) => return Err(public_api_error(error)),
    };
    let (height, api_utxos) = fetch_utxos_from_first_page(&api, &destination, first_page).await?;
    let next_height = height
        .checked_add(1)
        .ok_or_else(|| "La hauteur UTXO dépasse la limite sécuritaire locale.".to_owned())?;
    let owner: [u8; 32] = hex::decode(&destination)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(wallet_operation_failed)?;
    let reserved = lock_payments(&payments)?
        .reserved_inputs()
        .map_err(|_| pending_state_unavailable())?;
    let utxo_count = api_utxos.len();
    let utxos = api_utxos
        .iter()
        .cloned()
        .map(|utxo| convert_utxo(utxo, owner, &reserved))
        .collect::<Result<Vec<_>, _>>()?;
    let limit = PaymentPlanner::mainnet(owner)
        .and_then(|planner| planner.spending_limit(next_height, &utxos))
        .map_err(public_transaction_error)?;

    Ok(SendAvailability {
        available: TRUST_OFFICIAL_WALLET_GATEWAY_UTXOS,
        message: Some(OFFICIAL_GATEWAY_TRUST_MESSAGE.to_owned()),
        next_height: Some(next_height),
        utxo_count,
        spendable_atoms: Some(limit.available_atoms.to_string()),
        fee_atoms: Some(limit.fee_atoms.to_string()),
        maximum_atoms: Some(limit.maximum_atoms.to_string()),
    })
}

#[tauri::command]
async fn prepare_payment(
    state: State<'_, WalletState>,
    payments: State<'_, PaymentState>,
    api: State<'_, ApiClient>,
    independent: State<'_, IndependentUtxoClient>,
    recipient: String,
    amount: String,
) -> Result<PaymentSummary, String> {
    require_mainnet_send_enabled()?;
    let owner = {
        let engine = lock_engine(&state)?;
        engine.external_destination().map_err(|_| {
            "Déverrouillez le portefeuille avant de préparer un paiement.".to_owned()
        })?
    };
    let destination = hex::encode(owner);
    let amount_atoms = parse_cmfd(amount.trim())
        .map_err(|_| "Le montant CMFD est invalide ou comporte trop de décimales.".to_owned())?;
    let (height, api_utxos) = fetch_all_utxos(&api, &destination).await?;
    if !TRUST_OFFICIAL_WALLET_GATEWAY_UTXOS {
        return Err("L’envoi mainnet est désactivé par la politique de confiance UTXO.".to_owned());
    }
    let reserved = lock_payments(&payments)?
        .reserved_inputs()
        .map_err(|_| pending_state_unavailable())?;
    let utxos = api_utxos
        .iter()
        .cloned()
        .map(|utxo| convert_utxo(utxo, owner, &reserved))
        .collect::<Result<Vec<_>, _>>()?;
    let plan = PaymentPlanner::mainnet(owner)
        .and_then(|planner| {
            planner.plan(
                recipient.trim(),
                amount_atoms,
                MAINNET_MINIMUM_FEE_ATOMS,
                height
                    .checked_add(1)
                    .ok_or(cmfd_wallet_core::TransactionError::AmountOverflow)?,
                &utxos,
            )
        })
        .map_err(public_transaction_error)?;
    verify_selected_inputs(
        &api,
        &independent,
        &api_utxos,
        &plan.selected,
        plan.input_atoms,
        &destination,
        height,
    )
    .await?;
    let prepared = PreparedPayment::from_recipient(plan, recipient.trim())
        .map_err(|_| "L’adresse affichée ne correspond plus au paiement préparé.".to_owned())?;
    lock_payments(&payments)?
        .prepare(prepared)
        .map_err(|_| "Ce paiement ou l’un de ses UTXO est déjà en attente.".to_owned())
}

#[tauri::command]
async fn confirm_and_broadcast_payment(
    state: State<'_, WalletState>,
    payments: State<'_, PaymentState>,
    api: State<'_, ApiClient>,
    independent: State<'_, IndependentUtxoClient>,
    intent: String,
) -> Result<BroadcastOutcome, String> {
    require_mainnet_send_enabled()?;
    let plan = {
        let payments = lock_payments(&payments)?;
        payments
            .prepared(&intent)
            .map_err(|_| "Le récapitulatif a expiré; préparez de nouveau le paiement.".to_owned())?
            .plan
            .clone()
    };
    let owner = {
        let engine = lock_engine(&state)?;
        engine
            .external_destination()
            .map_err(|_| wallet_operation_failed())?
    };
    let destination = hex::encode(owner);
    let (height, latest_utxos) = fetch_all_utxos(&api, &destination).await?;
    verify_selected_inputs(
        &api,
        &independent,
        &latest_utxos,
        &plan.selected,
        plan.input_atoms,
        &destination,
        height,
    )
    .await?;
    let transaction = {
        let engine = lock_engine(&state)?;
        engine.sign_external(&plan).map_err(|_| {
            "La signature locale a échoué; aucune transaction n’a été diffusée.".to_owned()
        })?
    };
    let transaction_hex = transaction.frame_hex();
    let local_txid = transaction.txid_hex();
    let pending = lock_payments(&payments)?
        .record_before_broadcast(&intent, &transaction)
        .map_err(|_| {
            "L’état en attente n’a pas pu être enregistré; aucune diffusion n’a été tentée."
                .to_owned()
        })?;

    match api.broadcast(&transaction_hex).await {
        Ok(response) if response.txid == local_txid => {
            let payment = lock_payments(&payments)?
                .update(&local_txid, PendingPaymentState::Accepted, 0)
                .map_err(|_| pending_state_unavailable())?;
            Ok(BroadcastOutcome {
                payment,
                submitted: true,
                message: "Transaction acceptée par le service Common Foundry; elle n’est pas encore confirmée."
                    .to_owned(),
            })
        }
        Ok(_) => Ok(BroadcastOutcome {
            payment: pending,
            submitted: false,
            message: "La réponse du serveur ne correspond pas au TXID signé localement. L’état reste ambigu et aucune retransmission automatique ne sera faite."
                .to_owned(),
        }),
        Err(_) => Ok(BroadcastOutcome {
            payment: pending,
            submitted: false,
            message: "La réponse réseau ou HTTP est ambiguë. Les UTXO restent réservés jusqu’à une réconciliation explicite par TXID et aucune retransmission automatique ne sera faite."
                .to_owned(),
        }),
    }
}

#[tauri::command]
fn pending_payments(payments: State<'_, PaymentState>) -> Result<Vec<PendingPaymentView>, String> {
    Ok(lock_payments(&payments)?.views())
}

#[tauri::command]
async fn reconcile_pending_payments(
    payments: State<'_, PaymentState>,
    api: State<'_, ApiClient>,
) -> Result<Vec<PendingPaymentView>, String> {
    let txids = lock_payments(&payments)?.active_txids();
    for txid in txids {
        if let Ok(Some(status)) = api.transaction(&txid).await {
            let reconciled = reconciled_payment_state(&status);
            if let Some((state, confirmations)) = reconciled {
                lock_payments(&payments)?
                    .update(&txid, state, confirmations)
                    .map_err(|_| pending_state_unavailable())?;
            }
        }
    }
    Ok(lock_payments(&payments)?.views())
}

fn reconciled_payment_state(
    status: &cmfd_wallet_api::TransactionStatus,
) -> Option<(PendingPaymentState, u64)> {
    match status.status.to_ascii_lowercase().as_str() {
        "confirmed" if status.confirmations > 0 => {
            Some((PendingPaymentState::Confirmed, status.confirmations))
        }
        "accepted" | "mempool" | "pending" if status.confirmations == 0 => {
            Some((PendingPaymentState::Accepted, 0))
        }
        // Until the official service publishes reorg-safe terminality rules,
        // one remote observation cannot release locally reserved inputs.
        "conflicted" | "dropped" | "rejected" if status.confirmations == 0 => None,
        _ => None,
    }
}

fn mainnet_send_enabled() -> bool {
    TRUST_OFFICIAL_WALLET_GATEWAY_UTXOS && !cfg!(debug_assertions)
}

fn require_mainnet_send_enabled() -> Result<(), String> {
    mainnet_send_enabled()
        .then_some(())
        .ok_or_else(|| DEVELOPMENT_BUILD_SEND_MESSAGE.to_owned())
}

async fn fetch_all_utxos(
    api: &ApiClient,
    destination: &str,
) -> Result<(u64, Vec<ApiUtxo>), String> {
    let first_page = api
        .utxos(destination, None)
        .await
        .map_err(public_api_error)?;
    fetch_utxos_from_first_page(api, destination, first_page).await
}

async fn fetch_utxos_from_first_page(
    api: &ApiClient,
    destination: &str,
    first_page: UtxoPage,
) -> Result<(u64, Vec<ApiUtxo>), String> {
    let mut seen_cursors = HashSet::new();
    let mut seen_outpoints = HashSet::new();
    let mut height = None;
    let mut utxos = Vec::new();
    let mut page = first_page;
    for page_index in 0..MAX_UTXO_PAGES {
        if height
            .replace(page.height)
            .is_some_and(|value| value != page.height)
        {
            return Err("Les pages UTXO ne décrivent pas la même hauteur validée.".to_owned());
        }
        for utxo in page.utxos {
            if !seen_outpoints.insert((utxo.txid.clone(), utxo.vout)) {
                return Err(
                    "Le service a retourné un UTXO dupliqué; l’envoi est bloqué.".to_owned(),
                );
            }
            utxos.push(utxo);
            if utxos.len() > MAX_UTXOS {
                return Err("Le nombre d’UTXO dépasse la limite sécuritaire locale.".to_owned());
            }
        }
        if !page.has_more {
            return Ok((height.unwrap_or(page.height), utxos));
        }
        let next = page
            .next_cursor
            .ok_or_else(|| "La pagination UTXO est incomplète.".to_owned())?;
        if !seen_cursors.insert(next.clone()) {
            return Err("La pagination UTXO est invalide ou cyclique.".to_owned());
        }
        if page_index + 1 == MAX_UTXO_PAGES {
            break;
        }
        page = api
            .utxos(destination, Some(&next))
            .await
            .map_err(public_api_error)?;
    }
    Err("La pagination UTXO dépasse la limite sécuritaire locale.".to_owned())
}

/// Cross-check every selected input against the gateway's confirmed output and
/// an independently routed full node. An unavailable or disagreeing source
/// blocks signing rather than silently increasing the burned fee.
async fn verify_selected_inputs(
    api: &ApiClient,
    independent: &IndependentUtxoClient,
    reported: &[ApiUtxo],
    selected: &[OutPoint],
    expected_total: u64,
    owner_hex: &str,
    snapshot_height: u64,
) -> Result<(), String> {
    if selected.is_empty() {
        return Err(INPUT_VERIFICATION_ERROR.to_owned());
    }
    let mut selected_reports = HashMap::new();
    let mut total = 0_u64;
    for outpoint in selected {
        let txid = hex::encode(outpoint.txid);
        let report = reported
            .iter()
            .find(|utxo| utxo.txid == txid && utxo.vout == outpoint.index)
            .ok_or(INPUT_VERIFICATION_ERROR)?;
        total = total
            .checked_add(
                report
                    .value_atoms
                    .parse::<u64>()
                    .map_err(|_| INPUT_VERIFICATION_ERROR)?,
            )
            .ok_or(INPUT_VERIFICATION_ERROR)?;
        selected_reports.insert((txid, outpoint.index), report);
    }
    if total != expected_total {
        return Err(INPUT_VERIFICATION_ERROR.to_owned());
    }

    let mut txids = selected_reports
        .keys()
        .map(|(txid, _)| txid.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    txids.sort_unstable();
    for batch in txids.chunks(INPUT_LOOKUP_CONCURRENCY) {
        let lookups = batch
            .iter()
            .map(|txid| {
                let api = api.clone();
                let txid = txid.clone();
                tauri::async_runtime::spawn(async move {
                    let status = api
                        .transaction(&txid)
                        .await
                        .map_err(|_| INPUT_VERIFICATION_ERROR)?
                        .ok_or(INPUT_VERIFICATION_ERROR)?;
                    if !status.status.eq_ignore_ascii_case("confirmed")
                        || status
                            .block_height
                            .is_none_or(|height| height > snapshot_height)
                    {
                        return Err(INPUT_VERIFICATION_ERROR);
                    }
                    let block_id = status.block_id.ok_or(INPUT_VERIFICATION_ERROR)?;
                    let outputs = api
                        .transaction_outputs(&txid, &block_id)
                        .await
                        .map_err(|_| INPUT_VERIFICATION_ERROR)?;
                    Ok::<_, &'static str>((txid, outputs))
                })
            })
            .collect::<Vec<_>>();
        for lookup in lookups {
            let (txid, outputs) = lookup
                .await
                .map_err(|_| INPUT_VERIFICATION_ERROR)?
                .map_err(|_| INPUT_VERIFICATION_ERROR)?;
            for outpoint in selected
                .iter()
                .filter(|point| hex::encode(point.txid) == txid)
            {
                let report = selected_reports
                    .get(&(txid.clone(), outpoint.index))
                    .copied()
                    .ok_or(INPUT_VERIFICATION_ERROR)?;
                let output = outputs
                    .vout
                    .get(outpoint.index as usize)
                    .ok_or(INPUT_VERIFICATION_ERROR)?;
                verify_reported_output(report, output, owner_hex)?;
            }
        }
    }

    for batch in selected.chunks(INPUT_LOOKUP_CONCURRENCY) {
        let lookups = batch
            .iter()
            .map(|outpoint| {
                let independent = independent.clone();
                let txid = hex::encode(outpoint.txid);
                let vout = outpoint.index;
                tauri::async_runtime::spawn(async move {
                    independent
                        .utxo(&txid, vout)
                        .await
                        .map_err(|_| INDEPENDENT_VERIFICATION_ERROR)
                })
            })
            .collect::<Vec<_>>();
        for (outpoint, lookup) in batch.iter().zip(lookups) {
            let confirmed = lookup
                .await
                .map_err(|_| INDEPENDENT_VERIFICATION_ERROR)?
                .map_err(|_| INDEPENDENT_VERIFICATION_ERROR)?;
            let report = selected_reports
                .get(&(hex::encode(outpoint.txid), outpoint.index))
                .copied()
                .ok_or(INDEPENDENT_VERIFICATION_ERROR)?;
            verify_independent_output(report, &confirmed, owner_hex, snapshot_height)?;
        }
    }
    Ok(())
}

fn verify_independent_output(
    report: &ApiUtxo,
    independent: &IndependentUtxo,
    owner_hex: &str,
    wallet_snapshot_height: u64,
) -> Result<(), String> {
    if !independent.available
        || independent.value_atoms != report.value_atoms
        || independent.destination_hex != owner_hex
        || independent.spendable_height != report.spendable_height
        || independent
            .height
            .saturating_add(MAX_INDEPENDENT_NODE_LAG_BLOCKS)
            < wallet_snapshot_height
    {
        return Err(INDEPENDENT_VERIFICATION_ERROR.to_owned());
    }
    Ok(())
}

fn verify_reported_output(
    report: &ApiUtxo,
    output: &ApiTransactionOutput,
    owner_hex: &str,
) -> Result<(), String> {
    if output.destination_hex.as_deref() != Some(owner_hex)
        || output.value_atoms != report.value_atoms
    {
        return Err(INPUT_VERIFICATION_ERROR.to_owned());
    }
    Ok(())
}

fn convert_utxo(
    utxo: ApiUtxo,
    owner: [u8; 32],
    reserved: &HashSet<OutPoint>,
) -> Result<Utxo, String> {
    let txid: [u8; 32] = hex::decode(&utxo.txid)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Le service a retourné un identifiant UTXO invalide.".to_owned())?;
    let outpoint = OutPoint {
        txid,
        index: utxo.vout,
    };
    Ok(Utxo {
        outpoint,
        value_atoms: utxo
            .value_atoms
            .parse::<u64>()
            .map_err(|_| "Le service a retourné un montant UTXO invalide.".to_owned())?,
        destination: owner,
        spendable_height: utxo.spendable_height,
        known_spent: false,
        locally_reserved: reserved.contains(&outpoint),
    })
}

fn public_transaction_error(error: cmfd_wallet_core::TransactionError) -> String {
    use cmfd_wallet_core::TransactionError;
    match error {
        TransactionError::InvalidRecipient(_) | TransactionError::WrongNetwork => {
            "L’adresse de destination mainnet est invalide.".to_owned()
        }
        TransactionError::ZeroAmount => "Le montant doit être supérieur à zéro.".to_owned(),
        TransactionError::InsufficientFunds { .. } => {
            "Les fonds réellement dépensables sont insuffisants, frais compris.".to_owned()
        }
        TransactionError::FundsImmature { .. } => {
            "Les fonds présents sont encore immatures et ne peuvent pas être dépensés.".to_owned()
        }
        TransactionError::DuplicateIntent | TransactionError::ReservationConflict => {
            "Ce paiement ou l’un de ses UTXO est déjà en attente.".to_owned()
        }
        _ => "Le paiement ne satisfait pas les règles de consensus Common Foundry.".to_owned(),
    }
}

fn unlocked_destination(state: &State<'_, WalletState>) -> Result<String, String> {
    let engine = lock_engine(state)?;
    let status = engine
        .external_status(true)
        .map_err(|_| wallet_operation_failed())?;
    if !status.unlocked {
        return Err(
            "Déverrouillez le portefeuille avant d’accéder aux données financières.".to_owned(),
        );
    }
    status.destination_hex.ok_or_else(wallet_operation_failed)
}

fn lock_engine<'a>(state: &'a WalletState) -> Result<WalletGuard<'a>, String> {
    let mut engine = state
        .engine
        .lock()
        .map_err(|_| "Le service sécurisé du portefeuille est indisponible.".to_owned())?;
    let acquired_epoch = state.lifecycle_epoch.load(Ordering::Acquire);
    if !state.foreground.load(Ordering::Acquire) {
        engine.abort_external_operation();
        return Err("Le service sécurisé du portefeuille est indisponible.".to_owned());
    }
    Ok(WalletGuard {
        engine,
        foreground: &state.foreground,
        lifecycle_epoch: &state.lifecycle_epoch,
        acquired_epoch,
    })
}

fn lock_payments<'a>(state: &'a PaymentState) -> Result<PaymentGuard<'a>, String> {
    let mut store = state
        .store
        .lock()
        .map_err(|_| pending_state_unavailable())?;
    let acquired_epoch = state.lifecycle_epoch.load(Ordering::Acquire);
    if !state.foreground.load(Ordering::Acquire) {
        store.clear_prepared();
        return Err(pending_state_unavailable());
    }
    Ok(PaymentGuard {
        store,
        foreground: &state.foreground,
        lifecycle_epoch: &state.lifecycle_epoch,
        acquired_epoch,
    })
}

fn document_picker_returned(app: &AppHandle, wallet: &WalletState) {
    wallet.set_foreground(true);
    if let Some(payments) = app.try_state::<PaymentState>() {
        payments.set_foreground(true);
    }
}

fn pending_state_unavailable() -> String {
    "L’état local des transactions en attente est indisponible; l’envoi est bloqué.".to_owned()
}

fn with_engine_status(
    state: &State<'_, WalletState>,
    recovery_required: bool,
    operation: impl FnOnce(&mut WalletEngine) -> Result<EngineStatus, cmfd_wallet_engine::EngineError>,
) -> Result<PublicWalletStatus, String> {
    let mut engine = lock_engine(state)?;
    operation(&mut engine)
        .map(|status| PublicWalletStatus::from_engine(status, recovery_required))
        .map_err(|_| wallet_operation_failed())
}

fn wallet_operation_failed() -> String {
    "L’opération du portefeuille a échoué de façon sécuritaire.".to_owned()
}

fn secure_storage_unavailable() -> String {
    "Le stockage sécurisé Android est indisponible.".to_owned()
}

fn public_api_error(error: ApiError) -> String {
    match error {
        ApiError::Timeout | ApiError::Unreachable => {
            "Le service Common Foundry est temporairement inaccessible.".to_owned()
        }
        ApiError::Http { code, .. } if code == "work_check_pending" => {
            "Le serveur Common Foundry n’a pas encore validé les blocs nécessaires.".to_owned()
        }
        _ => "La réponse du service Common Foundry est invalide ou a été refusée.".to_owned(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_cmfd_android::init())
        .on_window_event(|window, event| {
            #[cfg(mobile)]
            {
                let foreground = match event {
                    tauri::WindowEvent::Suspended => Some(false),
                    tauri::WindowEvent::Resumed => Some(true),
                    _ => None,
                };
                if let Some(foreground) = foreground {
                    let app = window.app_handle();
                    if let Some(wallet) = app.try_state::<WalletState>() {
                        wallet.set_foreground(foreground);
                    }
                    if let Some(payments) = app.try_state::<PaymentState>() {
                        payments.set_foreground(foreground);
                    }
                }
            }

            #[cfg(desktop)]
            let _ = (window, event);
        })
        .setup(|app| {
            #[cfg(mobile)]
            app.handle().plugin(tauri_plugin_barcode_scanner::init())?;
            let private_directory = app.path().app_data_dir()?.join("wallet");
            app.manage(WalletState::new(WalletEngine::new(&private_directory)));
            app.manage(PaymentState::new(
                PaymentStore::load(private_directory.join("pending-transactions.json"))
                    .map_err(|_| std::io::Error::other("pending payment state is invalid"))?,
            ));
            let api = ApiClient::new().map_err(|_| {
                std::io::Error::other("Common Foundry API configuration is invalid")
            })?;
            app.manage(api);
            let independent = IndependentUtxoClient::new().map_err(|_| {
                std::io::Error::other("Independent UTXO service configuration is invalid")
            })?;
            app.manage(independent);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_status,
            create_wallet,
            restore_wallet,
            unlock_wallet,
            lock_wallet,
            export_wallet,
            wallet_overview,
            send_availability,
            prepare_payment,
            confirm_and_broadcast_payment,
            pending_payments,
            reconcile_pending_payments,
        ])
        .run(tauri::generate_context!())
        .expect("Common Foundry Android wallet failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmfd_wallet_api::TransactionStatus;

    fn remote_status(status: &str, confirmations: u64) -> TransactionStatus {
        TransactionStatus {
            txid: "11".repeat(32),
            status: status.to_owned(),
            block_height: (confirmations > 0).then_some(42),
            block_id: (confirmations > 0).then(|| "22".repeat(32)),
            confirmations,
            validated_height: (confirmations > 0).then_some(41 + confirmations),
            timestamp: Some(1_700_000_000),
        }
    }

    #[test]
    fn reconciliation_handles_confirmation_reorg_and_unknown_states_fail_closed() {
        assert_eq!(
            reconciled_payment_state(&remote_status("confirmed", 4)),
            Some((PendingPaymentState::Confirmed, 4))
        );
        assert_eq!(
            reconciled_payment_state(&remote_status("mempool", 0)),
            Some((PendingPaymentState::Accepted, 0))
        );
        assert_eq!(
            reconciled_payment_state(&remote_status("conflicted", 0)),
            None
        );
        assert_eq!(reconciled_payment_state(&remote_status("dropped", 0)), None);
        assert_eq!(
            reconciled_payment_state(&remote_status("rejected", 0)),
            None
        );
        assert_eq!(reconciled_payment_state(&remote_status("future", 0)), None);
    }

    #[test]
    fn official_gateway_trust_disclosure_is_explicit() {
        assert!(OFFICIAL_GATEWAY_TRUST_MESSAGE.contains("passerelle officielle"));
    }

    #[test]
    fn selected_input_cross_check_rejects_fee_and_owner_mismatches() {
        let report = ApiUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value_atoms: "100000000".to_owned(),
            spendable_height: 44,
        };
        let owner = "22".repeat(32);
        let mut output = ApiTransactionOutput {
            value_atoms: report.value_atoms.clone(),
            destination_hex: Some(owner.clone()),
        };
        assert!(verify_reported_output(&report, &output, &owner).is_ok());
        output.value_atoms = "200000000".to_owned();
        assert!(verify_reported_output(&report, &output, &owner).is_err());
        output.value_atoms = report.value_atoms.clone();
        output.destination_hex = Some("33".repeat(32));
        assert!(verify_reported_output(&report, &output, &owner).is_err());
        output.destination_hex = None;
        assert!(verify_reported_output(&report, &output, &owner).is_err());
    }

    #[test]
    fn independent_node_must_agree_on_value_owner_maturity_and_availability() {
        let owner = "22".repeat(32);
        let report = ApiUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value_atoms: "100000000".to_owned(),
            spendable_height: 100,
        };
        let mut independent = IndependentUtxo {
            network_id: hex::encode(cmfd_wallet_core::network::MAINNET_NETWORK_ID),
            tip: "33".repeat(32),
            height: 101,
            txid: report.txid.clone(),
            vout: report.vout,
            value_atoms: report.value_atoms.clone(),
            destination_hex: owner.clone(),
            spendable_height: report.spendable_height,
            available: true,
        };
        assert!(verify_independent_output(&report, &independent, &owner, 105).is_ok());
        independent.value_atoms = "200000000".to_owned();
        assert!(verify_independent_output(&report, &independent, &owner, 105).is_err());
        independent.value_atoms = report.value_atoms.clone();
        independent.destination_hex = "44".repeat(32);
        assert!(verify_independent_output(&report, &independent, &owner, 105).is_err());
        independent.destination_hex = owner.clone();
        independent.available = false;
        assert!(verify_independent_output(&report, &independent, &owner, 105).is_err());
        independent.available = true;
        assert!(verify_independent_output(&report, &independent, &owner, 108).is_err());
    }

    #[test]
    fn debug_builds_fail_closed_before_mainnet_signing_or_broadcast() {
        assert!(!mainnet_send_enabled());
        assert_eq!(
            require_mainnet_send_enabled(),
            Err(DEVELOPMENT_BUILD_SEND_MESSAGE.to_owned())
        );
    }

    #[test]
    fn a_suspend_epoch_locks_after_an_in_flight_wallet_guard_even_if_resumed() {
        let private_directory =
            std::env::temp_dir().join(format!("cmfd-wallet-lifecycle-{}", std::process::id()));
        let state = WalletState::new(WalletEngine::new(private_directory));
        {
            let mut engine = lock_engine(&state).unwrap();
            engine
                .prepare_external_create(b"synthetic lifecycle passphrase", false)
                .unwrap();
            assert!(engine.external_status(false).unwrap().unlocked);
            state.set_foreground(false);
            state.set_foreground(true);
            assert!(engine.external_status(false).unwrap().unlocked);
        }
        assert!(
            !lock_engine(&state)
                .unwrap()
                .external_status(false)
                .unwrap()
                .unlocked
        );
    }

    #[test]
    fn an_explicit_document_picker_return_can_finish_the_original_operation() {
        let private_directory = std::env::temp_dir().join(format!(
            "cmfd-wallet-document-return-{}",
            std::process::id()
        ));
        let state = WalletState::new(WalletEngine::new(private_directory));
        {
            let mut engine = lock_engine(&state).unwrap();
            engine
                .prepare_external_create(b"synthetic document passphrase", false)
                .unwrap();
            state.set_foreground(false);
            engine.acknowledge_external_activity_return();
        }
        assert!(
            lock_engine(&state)
                .unwrap()
                .external_status(false)
                .unwrap()
                .unlocked
        );
    }

    #[test]
    fn a_suspend_epoch_discards_an_in_flight_payment_even_if_resumed() {
        let owner: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let plan = PaymentPlanner::mainnet(owner)
            .unwrap()
            .plan(
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                1,
                MAINNET_MINIMUM_FEE_ATOMS,
                100,
                &[Utxo {
                    outpoint: OutPoint {
                        txid: [0x41; 32],
                        index: 0,
                    },
                    value_atoms: MAINNET_MINIMUM_FEE_ATOMS + 2,
                    destination: owner,
                    spendable_height: 99,
                    known_spent: false,
                    locally_reserved: false,
                }],
            )
            .unwrap();
        let prepared = PreparedPayment::new(plan);
        let intent = prepared.summary.intent.clone();
        let path = std::env::temp_dir().join(format!(
            "cmfd-wallet-payment-lifecycle-{}.json",
            std::process::id()
        ));
        let state = PaymentState::new(PaymentStore::load(path).unwrap());
        {
            let mut payments = lock_payments(&state).unwrap();
            payments.prepare(prepared).unwrap();
            state.set_foreground(false);
            state.set_foreground(true);
            assert!(payments.prepared(&intent).is_ok());
        }
        assert!(lock_payments(&state).unwrap().prepared(&intent).is_err());
    }

    #[test]
    fn contradictory_remote_states_never_release_or_confirm_inputs() {
        assert_eq!(
            reconciled_payment_state(&remote_status("conflicted", 2)),
            None
        );
        assert_eq!(reconciled_payment_state(&remote_status("dropped", 1)), None);
        assert_eq!(
            reconciled_payment_state(&remote_status("confirmed", 0)),
            None
        );
    }

    #[test]
    fn independent_synthetic_public_utxos_plan_round_trip_offline() {
        let owner: [u8; 32] =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        let api_utxo = ApiUtxo {
            txid: "42".repeat(32),
            vout: 0,
            value_atoms: "100000000".to_owned(),
            spendable_height: 1,
        };
        let utxo = convert_utxo(api_utxo, owner, &HashSet::new()).unwrap();
        let plan = PaymentPlanner::mainnet(owner)
            .unwrap()
            .plan(
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                30_000_000,
                MAINNET_MINIMUM_FEE_ATOMS,
                2,
                &[utxo],
            )
            .unwrap();

        assert_eq!(plan.amount_atoms, 30_000_000);
        assert_eq!(plan.fee_atoms, 10_000_000);
        assert_eq!(plan.change_atoms, 60_000_000);
        assert_eq!(plan.input_atoms, 100_000_000);
        assert_eq!(plan.selected.len(), 1);

        let second_owner: [u8; 32] =
            hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap()
                .try_into()
                .unwrap();
        let return_plan = PaymentPlanner::mainnet(second_owner)
            .unwrap()
            .plan(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                10_000_000,
                MAINNET_MINIMUM_FEE_ATOMS,
                2,
                &[Utxo {
                    outpoint: OutPoint {
                        txid: [0x55; 32],
                        index: 0,
                    },
                    value_atoms: 30_000_000,
                    destination: second_owner,
                    spendable_height: 1,
                    known_spent: false,
                    locally_reserved: false,
                }],
            )
            .unwrap();
        assert_eq!(return_plan.amount_atoms, 10_000_000);
        assert_eq!(return_plan.fee_atoms, 10_000_000);
        assert_eq!(return_plan.change_atoms, 10_000_000);
    }
}
