import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Language = "en" | "fr";
export type LanguagePreference = "automatic" | Language;
export type ThemePreference = "light" | "dark";

export const LANGUAGE_STORAGE_KEY = "cmfd-wallet-language";
export const THEME_STORAGE_KEY = "cmfd-wallet-theme";

const en = {
  appSubtitle: "Android Wallet",
  settings: "Settings",
  settingsTitle: "Settings",
  closeSettings: "Close settings",
  appearance: "Appearance",
  language: "Language",
  walletSection: "Wallet",
  about: "About",
  light: "Light",
  lightDescription: "Warm off-white surfaces with copper accents.",
  dark: "Dark",
  darkDescription: "Deep charcoal surfaces with copper accents.",
  automatic: "Automatic",
  automaticDescription: "Uses the phone language; English is the fallback.",
  english: "English",
  french: "Français",
  backupShortcut: "Open wallet backup",
  backupShortcutHelp: "Opens the existing encrypted export screen.",
  backupUnavailable: "Unlock a configured wallet to export a backup.",
  appName: "Common Foundry Wallet",
  version: "Version {version}",
  network: "Network: Common Foundry Mainnet",
  openSource: "Open-source Android wallet. This development build is not presented as independently audited.",
  openingWallet: "Opening wallet…",
  secureServiceUnavailable: "The secure wallet service is unavailable.",
  mainnetEyebrow: "CMFD MAINNET",
  welcomeTitle: "Your wallet, on your phone.",
  welcomeBody: "Create a new identity or restore an official backup. The private key remains in the native Rust layer and the local wallet is wrapped by Android Keystore.",
  walletActions: "Wallet actions",
  createWallet: "Create a wallet",
  restoreBackup: "Restore a backup",
  activationNotice: "No wallet is activated until Android has written and read back your encrypted backup.",
  backupLossWarning: "Keep another encrypted backup outside this phone and store its passphrase separately. If the phone and your only backup are lost, your CMFD cannot be recovered.",
  createAndBackup: "Create and back up",
  createExplanation: "Choose a passphrase of at least 12 bytes. Android will then ask where to save the backup required for recovery.",
  chooseBackupLocation: "Choose backup location",
  restoreTitle: "Restore a backup",
  restoreExplanation: "Android will open the document picker. The backup and passphrase are authenticated before any local data is changed.",
  chooseBackup: "Choose backup",
  recoveryRequired: "RECOVERY REQUIRED",
  keystoreUnavailableTitle: "Android Keystore key unavailable",
  keystoreUnavailableBody: "The local copy can no longer be decrypted. It will not be erased or replaced before the official backup has been fully authenticated.",
  restoreOfficialBackup: "Restore the official backup",
  restoreOfficialExplanation: "Choose your backup file and enter its passphrase. The inaccessible encrypted local copy will be archived before the restored wallet is activated.",
  chooseAuthenticateBackup: "Choose and authenticate backup",
  walletLocked: "WALLET LOCKED",
  unlockRequired: "Unlock required",
  unlockPrivacy: "The address and financial data remain hidden from the interface until authentication.",
  passphrase: "Passphrase",
  passphraseExplanation: "The passphrase is sent once to the native layer and is never stored in Web storage.",
  unlock: "Unlock",
  passphraseMinimum: "The passphrase must contain at least 12 bytes.",
  passphraseMismatch: "The two passphrases do not match.",
  confirmPassphrase: "Confirm passphrase",
  secureProcessing: "Secure processing…",
  back: "Back",
  identityUnavailable: "Wallet identity unavailable.",
  walletTitle: "CMFD Wallet",
  lock: "Lock",
  walletSections: "Wallet sections",
  overview: "Overview",
  receive: "Receive",
  send: "Send",
  backup: "Backup",
  realBalance: "Live balance",
  refreshing: "Refreshing…",
  refresh: "Refresh",
  staleData: "The last valid data remains displayed.",
  loadingMainnet: "Loading validated mainnet data…",
  available: "Available",
  confirmed: "Confirmed",
  immature: "Immature",
  acceptedHeight: "Accepted height {height}; validated height {validated}.",
  unavailable: "unavailable",
  mempoolIncluded: " The mempool is included.",
  mempoolExcluded: " The mempool is not included.",
  recentTransactions: "Recent transactions",
  noTransactions: "No recent transaction was returned for this address.",
  historyOutgoing: "Outgoing transaction",
  historyInternal: "Internal transaction",
  historyPending: "Pending transaction",
  historyUnknown: "Transaction with an unrecognized type",
  historyAmountUnavailable: "The address-history API does not expose a trustworthy outgoing amount; received change is not shown as income.",
  oneConfirmation: "1 confirmation",
  manyConfirmations: "{count} confirmations",
  olderHistory: "Older pages exist; loading them will be enabled when the history pagination API is confirmed.",
  receiveEyebrow: "RECEIVE",
  mainnetAddress: "Mainnet address",
  receiveQrLabel: "QR code for the receiving address",
  addressCopied: "Address copied",
  copyAddress: "Copy address",
  receiveQrNotice: "The QR code contains exactly the official cmfd1… address, with no private key or imposed amount.",
  sendEyebrow: "SEND",
  preparePayment: "Prepare a payment",
  recipientAddress: "Recipient address",
  scan: "Scan",
  amountCmfd: "CMFD amount",
  spendingInformation: "Spending information",
  availableBalance: "Available balance",
  expectedNetworkFee: "Expected network fee",
  maximumSendable: "Maximum sendable after fees",
  verifyUtxoFees: "Check UTXOs and fees",
  verifying: "Checking…",
  cameraPermissionRequired: "Camera permission is required only while scanning the QR code.",
  invalidQr: "The QR code does not contain a recognized Common Foundry mainnet address.",
  scanCancelled: "QR scanning was cancelled or failed.",
  checkingUtxo: "Checking UTXO availability…",
  utxoUnavailable: "UTXOs are unavailable.",
  gatewayRespondsOne: "The UTXO API returned 1 output. Signing remains local; broadcasting requires a second explicit confirmation.",
  gatewayRespondsMany: "The UTXO API returned {count} outputs. Signing remains local; broadcasting requires a second explicit confirmation.",
  irreversibleConfirmation: "Irreversible confirmation",
  recipient: "Recipient",
  recipientHex: "Recipient (hexadecimal)",
  recipientBech32m: "Address provided (cmfd1…)",
  amount: "Amount",
  expectedFee: "Expected network fee (burned)",
  change: "Change",
  selectedInputs: "Selected inputs",
  broadcastAuthorization: "I understand that a separate node checks the inputs but this phone does not validate the full chain. I confirm this address, amount and expected fee, and authorize exactly one mainnet broadcast attempt.",
  signingBroadcast: "Signing and broadcasting…",
  signBroadcastOnce: "Sign and broadcast once",
  cancel: "Cancel",
  trackedTransactions: "Tracked local transactions",
  checkConfirmations: "Check confirmations",
  noPending: "No local transaction is pending.",
  pendingUnknown: "Ambiguous broadcast — UTXOs reserved",
  pendingAccepted: "Accepted — awaiting confirmation",
  pendingConfirmedOne: "1 confirmation",
  pendingConfirmedMany: "{count} confirmations",
  pendingConflicted: "Conflicting",
  pendingDropped: "Rejected",
  backupEyebrow: "BACKUP",
  exportOfficialCopy: "Export an official encrypted backup",
  exportDescription: "Re-enter the current passphrase. It authenticates the local wallet before creating the portable copy. Keep the file and passphrase separate.",
  currentPassphrase: "Current passphrase",
  exporting: "Exporting…",
  chooseLocation: "Choose location",
  exportSuccess: "Encrypted backup written and read back successfully.",
  keystoreNotIncluded: "The Android Keystore key is never included in the exported file.",
  genericFailure: "The operation failed safely. Try again without closing the application.",
  dateUnavailable: "Date unavailable",
} as const;

const fr = {
  appSubtitle: "Portefeuille Android",
  settings: "Paramètres",
  settingsTitle: "Paramètres",
  closeSettings: "Fermer les paramètres",
  appearance: "Apparence",
  language: "Langue",
  walletSection: "Portefeuille",
  about: "À propos",
  light: "Clair",
  lightDescription: "Surfaces blanc cassé et accents cuivrés.",
  dark: "Sombre",
  darkDescription: "Surfaces anthracite et accents cuivrés.",
  automatic: "Automatique",
  automaticDescription: "Utilise la langue du téléphone; l’anglais est la langue de secours.",
  english: "English",
  french: "Français",
  backupShortcut: "Ouvrir la sauvegarde du portefeuille",
  backupShortcutHelp: "Ouvre l’écran existant d’exportation chiffrée.",
  backupUnavailable: "Déverrouillez un portefeuille configuré pour exporter une sauvegarde.",
  appName: "Common Foundry Wallet",
  version: "Version {version}",
  network: "Réseau : Common Foundry Mainnet",
  openSource: "Portefeuille Android open source. Cette version de développement n’est pas présentée comme auditée indépendamment.",
  openingWallet: "Ouverture du portefeuille…",
  secureServiceUnavailable: "Le service sécurisé du portefeuille est indisponible.",
  mainnetEyebrow: "MAINNET CMFD",
  welcomeTitle: "Votre portefeuille, sur votre téléphone.",
  welcomeBody: "Créez une nouvelle identité ou restaurez une sauvegarde officielle. La clé privée reste dans la couche Rust native et le portefeuille local est enveloppé par Android Keystore.",
  walletActions: "Actions de portefeuille",
  createWallet: "Créer un portefeuille",
  restoreBackup: "Restaurer une sauvegarde",
  activationNotice: "Aucun portefeuille n’est activé tant que votre sauvegarde chiffrée n’a pas été écrite et relue par Android.",
  backupLossWarning: "Conservez une autre sauvegarde chiffrée hors de ce téléphone et gardez sa phrase secrète séparément. Si le téléphone et votre seule sauvegarde sont perdus, vos CMFD ne pourront pas être récupérés.",
  createAndBackup: "Créer et sauvegarder",
  createExplanation: "Choisissez une phrase secrète d’au moins 12 octets. Android vous demandera ensuite où enregistrer la sauvegarde indispensable à la récupération.",
  chooseBackupLocation: "Choisir l’emplacement de sauvegarde",
  restoreTitle: "Restaurer une sauvegarde",
  restoreExplanation: "Android ouvrira le sélecteur de documents. La sauvegarde et la phrase secrète sont authentifiées avant toute modification locale.",
  chooseBackup: "Choisir la sauvegarde",
  recoveryRequired: "RÉCUPÉRATION REQUISE",
  keystoreUnavailableTitle: "Clé Android Keystore inaccessible",
  keystoreUnavailableBody: "La copie locale ne peut plus être déchiffrée. Elle ne sera ni effacée ni remplacée avant l’authentification complète de votre sauvegarde officielle.",
  restoreOfficialBackup: "Restaurer la sauvegarde officielle",
  restoreOfficialExplanation: "Choisissez votre fichier de sauvegarde et entrez sa phrase secrète. L’ancienne copie locale chiffrée sera archivée avant l’activation de la restauration.",
  chooseAuthenticateBackup: "Choisir et authentifier la sauvegarde",
  walletLocked: "PORTEFEUILLE VERROUILLÉ",
  unlockRequired: "Déverrouillage requis",
  unlockPrivacy: "L’adresse et les données financières restent absentes de l’interface avant authentification.",
  passphrase: "Phrase secrète",
  passphraseExplanation: "La phrase est transmise une seule fois à la couche native et n’est jamais enregistrée dans le stockage Web.",
  unlock: "Déverrouiller",
  passphraseMinimum: "La phrase secrète doit contenir au moins 12 octets.",
  passphraseMismatch: "Les deux phrases secrètes ne correspondent pas.",
  confirmPassphrase: "Confirmer la phrase",
  secureProcessing: "Traitement sécurisé…",
  back: "Retour",
  identityUnavailable: "Identité du portefeuille indisponible.",
  walletTitle: "Portefeuille CMFD",
  lock: "Verrouiller",
  walletSections: "Sections du portefeuille",
  overview: "Aperçu",
  receive: "Recevoir",
  send: "Envoyer",
  backup: "Sauvegarde",
  realBalance: "Solde réel",
  refreshing: "Actualisation…",
  refresh: "Actualiser",
  staleData: "Les dernières données valides restent affichées.",
  loadingMainnet: "Chargement des données mainnet validées…",
  available: "Disponible",
  confirmed: "Confirmé",
  immature: "Immature",
  acceptedHeight: "Hauteur acceptée {height}; hauteur validée {validated}.",
  unavailable: "indisponible",
  mempoolIncluded: " Le mempool est inclus.",
  mempoolExcluded: " Le mempool n’est pas inclus.",
  recentTransactions: "Transactions récentes",
  noTransactions: "Aucune transaction récente n’a été retournée pour cette adresse.",
  historyOutgoing: "Transaction sortante",
  historyInternal: "Transaction interne",
  historyPending: "Transaction en attente",
  historyUnknown: "Transaction de type non reconnu",
  historyAmountUnavailable: "L’API d’historique d’adresse ne fournit pas de montant sortant fiable; la monnaie rendue reçue n’est pas affichée comme un revenu.",
  oneConfirmation: "1 confirmation",
  manyConfirmations: "{count} confirmations",
  olderHistory: "Des pages plus anciennes existent; leur chargement sera activé lorsque l’API de pagination de l’historique sera confirmée.",
  receiveEyebrow: "RECEVOIR",
  mainnetAddress: "Adresse mainnet",
  receiveQrLabel: "Code QR de l’adresse de réception",
  addressCopied: "Adresse copiée",
  copyAddress: "Copier l’adresse",
  receiveQrNotice: "Le code QR contient exactement l’adresse officielle cmfd1…, sans clé privée ni montant imposé.",
  sendEyebrow: "ENVOYER",
  preparePayment: "Préparer un paiement",
  recipientAddress: "Adresse du destinataire",
  scan: "Scanner",
  amountCmfd: "Montant CMFD",
  spendingInformation: "Informations de dépense",
  availableBalance: "Solde disponible",
  expectedNetworkFee: "Frais réseau prévus",
  maximumSendable: "Maximum envoyable après les frais",
  verifyUtxoFees: "Vérifier les UTXO et les frais",
  verifying: "Vérification…",
  cameraPermissionRequired: "La permission caméra est nécessaire uniquement pendant la lecture du code QR.",
  invalidQr: "Le code QR ne contient pas une adresse Common Foundry mainnet reconnue.",
  scanCancelled: "La lecture du code QR a été annulée ou a échoué.",
  checkingUtxo: "Vérification de la disponibilité des UTXO…",
  utxoUnavailable: "Les UTXO ne sont pas disponibles.",
  gatewayRespondsOne: "L’API UTXO répond avec 1 sortie. La signature reste locale; la diffusion nécessite une seconde confirmation explicite.",
  gatewayRespondsMany: "L’API UTXO répond avec {count} sorties. La signature reste locale; la diffusion nécessite une seconde confirmation explicite.",
  irreversibleConfirmation: "Confirmation irréversible",
  recipient: "Destinataire",
  recipientHex: "Destinataire (hexadécimal)",
  recipientBech32m: "Adresse fournie (cmfd1…)",
  amount: "Montant",
  expectedFee: "Frais réseau prévus (détruits)",
  change: "Monnaie rendue",
  selectedInputs: "Entrées sélectionnées",
  broadcastAuthorization: "Je comprends qu’un nœud distinct vérifie les entrées, mais que ce téléphone ne valide pas toute la chaîne. Je confirme cette adresse, ce montant et ces frais prévus, et j’autorise une seule tentative de diffusion mainnet.",
  signingBroadcast: "Signature et diffusion…",
  signBroadcastOnce: "Signer et diffuser une fois",
  cancel: "Annuler",
  trackedTransactions: "Transactions locales suivies",
  checkConfirmations: "Vérifier les confirmations",
  noPending: "Aucune transaction locale en attente.",
  pendingUnknown: "Diffusion ambiguë — UTXO réservés",
  pendingAccepted: "Acceptée — en attente de confirmation",
  pendingConfirmedOne: "1 confirmation",
  pendingConfirmedMany: "{count} confirmations",
  pendingConflicted: "En conflit",
  pendingDropped: "Refusée",
  backupEyebrow: "SAUVEGARDE",
  exportOfficialCopy: "Exporter une sauvegarde officielle chiffrée",
  exportDescription: "Entrez de nouveau la phrase secrète actuelle. Elle authentifie le portefeuille local avant la création de la copie portable. Conservez le fichier et la phrase séparément.",
  currentPassphrase: "Phrase secrète actuelle",
  exporting: "Exportation…",
  chooseLocation: "Choisir l’emplacement",
  exportSuccess: "Sauvegarde chiffrée écrite et relue avec succès.",
  keystoreNotIncluded: "La clé Android Keystore n’est jamais incluse dans le fichier exporté.",
  genericFailure: "L’opération a échoué de façon sécuritaire. Réessayez sans fermer l’application.",
  dateUnavailable: "Date indisponible",
} satisfies Record<keyof typeof en, string>;

export type TranslationKey = keyof typeof en;
export type Translate = (
  key: TranslationKey,
  values?: Record<string, string | number>,
) => string;

const translations: Record<Language, Record<TranslationKey, string>> = { en, fr };

export function resolveLanguage(
  preference: LanguagePreference,
  deviceLanguage: string = globalThis.navigator?.language ?? "en",
): Language {
  if (preference !== "automatic") return preference;
  return deviceLanguage.toLowerCase().split("-")[0] === "fr" ? "fr" : "en";
}

function storedLanguage(): LanguagePreference {
  try {
    const value = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    return value === "en" || value === "fr" || value === "automatic"
      ? value
      : "automatic";
  } catch {
    return "automatic";
  }
}

function storedTheme(): ThemePreference {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

interface I18nValue {
  language: Language;
  languagePreference: LanguagePreference;
  setLanguagePreference: (preference: LanguagePreference) => void;
  theme: ThemePreference;
  setTheme: (theme: ThemePreference) => void;
  t: Translate;
}

const I18nContext = createContext<I18nValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [languagePreference, setLanguagePreference] = useState(storedLanguage);
  const [theme, setTheme] = useState(storedTheme);
  const [deviceLanguage, setDeviceLanguage] = useState(
    () => globalThis.navigator?.language ?? "en",
  );
  const language = resolveLanguage(languagePreference, deviceLanguage);

  useEffect(() => {
    const update = () => setDeviceLanguage(globalThis.navigator?.language ?? "en");
    globalThis.addEventListener?.("languagechange", update);
    return () => globalThis.removeEventListener?.("languagechange", update);
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(LANGUAGE_STORAGE_KEY, languagePreference);
    } catch {
      // A preference failure must never affect wallet operations.
    }
  }, [languagePreference]);

  useEffect(() => {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // A preference failure must never affect wallet operations.
    }
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
  }, [theme]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  const t = useMemo<Translate>(() => {
    return (key, values = {}) =>
      Object.entries(values).reduce(
        (text, [name, value]) => text.replaceAll(`{${name}}`, String(value)),
        translations[language][key],
      );
  }, [language]);

  const value = useMemo(
    () => ({
      language,
      languagePreference,
      setLanguagePreference,
      theme,
      setTheme,
      t,
    }),
    [language, languagePreference, theme, t],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext);
  if (!value) throw new Error("I18nProvider is missing");
  return value;
}

const englishNativeMessages = new Map<string, string>([
  ["Phrase secrète invalide.", "Invalid passphrase."],
  ["Création annulée: aucune clé locale n’a été activée sans sauvegarde vérifiée.", "Creation cancelled: no local key was activated without a verified backup."],
  ["La sauvegarde a été créée, mais l’activation locale a échoué. Conservez la sauvegarde et utilisez Restaurer.", "The backup was created, but local activation failed. Keep the backup and use Restore."],
  ["Un portefeuille accessible existe déjà; aucune donnée n’a été remplacée.", "An accessible wallet already exists; no data was replaced."],
  ["Restauration annulée ou sauvegarde illisible.", "Restore was cancelled or the backup could not be read."],
  ["La sauvegarde, le réseau ou la phrase secrète est invalide.", "The backup, network or passphrase is invalid."],
  ["La sauvegarde est valide, mais Android Keystore n’a pas pu activer le portefeuille.", "The backup is valid, but Android Keystore could not activate the wallet."],
  ["Aucun portefeuille local n’est configuré.", "No local wallet is configured."],
  ["La clé Android Keystore est inaccessible ou les données locales sont endommagées. Restaurez votre sauvegarde officielle.", "The Android Keystore key is unavailable or local data is damaged. Restore your official backup."],
  ["La clé Android Keystore est inaccessible; aucune sauvegarde n’a été exportée.", "The Android Keystore key is unavailable; no backup was exported."],
  ["Le portefeuille doit être déverrouillé et la phrase secrète doit être valide.", "The wallet must be unlocked and the passphrase must be valid."],
  ["Exportation annulée ou impossible à vérifier.", "Export was cancelled or could not be verified."],
  ["Chaque entrée de la passerelle officielle est vérifiée avant signature auprès d’un nœud Falkenstein distinct. Une divergence ou une indisponibilité bloque l’envoi. Le téléphone ne valide pas lui-même toute la chaîne; une compromission des deux services pourrait encore fausser les frais.", "Every official gateway input is checked against a separate Falkenstein node before signing. A mismatch or outage blocks sending. The phone does not validate the full chain itself; compromise of both services could still misstate fees."],
  ["Le nœud de vérification indépendant est indisponible ou ne confirme pas les entrées sélectionnées. L’envoi est bloqué.", "The independent verification node is unavailable or does not confirm the selected inputs. Sending is blocked."],
  ["Les valeurs des entrées ne correspondent pas aux transactions confirmées. L’envoi est bloqué; réessayez après synchronisation du service.", "Input values do not match confirmed transactions. Sending is blocked; try again after the service synchronizes."],
  ["Le serveur valide encore les blocs nécessaires. L’envoi demeure verrouillé pour éviter de dépenser des UTXO non vérifiés.", "The server is still validating the required blocks. Sending remains locked to avoid spending unverified UTXOs."],
  ["Déverrouillez le portefeuille avant de préparer un paiement.", "Unlock the wallet before preparing a payment."],
  ["Le montant CMFD est invalide ou comporte trop de décimales.", "The CMFD amount is invalid or has too many decimal places."],
  ["L’envoi mainnet est désactivé par la politique de confiance UTXO.", "Mainnet sending is disabled by the UTXO trust policy."],
  ["L’envoi mainnet est désactivé dans les versions de développement débogables. Utilisez une version release signée et validée.", "Mainnet sending is disabled in debuggable development builds. Use a signed and validated release build."],
  ["Ce paiement ou l’un de ses UTXO est déjà en attente.", "This payment or one of its UTXOs is already pending."],
  ["Le récapitulatif a expiré; préparez de nouveau le paiement.", "The summary expired; prepare the payment again."],
  ["La signature locale a échoué; aucune transaction n’a été diffusée.", "Local signing failed; no transaction was broadcast."],
  ["L’état en attente n’a pas pu être enregistré; aucune diffusion n’a été tentée.", "The pending state could not be saved; no broadcast was attempted."],
  ["Transaction acceptée par le service Common Foundry; elle n’est pas encore confirmée.", "The Common Foundry service accepted the transaction; it is not confirmed yet."],
  ["La réponse du serveur ne correspond pas au TXID signé localement. L’état reste ambigu et aucune retransmission automatique ne sera faite.", "The server response does not match the locally signed TXID. The state remains ambiguous and no automatic rebroadcast will occur."],
  ["La réponse réseau ou HTTP est ambiguë. Les UTXO restent réservés jusqu’à une réconciliation explicite par TXID et aucune retransmission automatique ne sera faite.", "The network or HTTP response is ambiguous. UTXOs remain reserved until explicit TXID reconciliation, and no automatic rebroadcast will occur."],
  ["L’adresse de destination mainnet est invalide.", "The mainnet destination address is invalid."],
  ["Le montant doit être supérieur à zéro.", "The amount must be greater than zero."],
  ["Les fonds réellement dépensables sont insuffisants, frais compris.", "Spendable funds are insufficient, including fees."],
  ["Les fonds présents sont encore immatures et ne peuvent pas être dépensés.", "The available funds are still immature and cannot be spent."],
  ["Le paiement ne satisfait pas les règles de consensus Common Foundry.", "The payment does not satisfy Common Foundry consensus rules."],
  ["Déverrouillez le portefeuille avant d’accéder aux données financières.", "Unlock the wallet before accessing financial data."],
  ["L’état local des transactions en attente est indisponible; l’envoi est bloqué.", "The local pending-transaction state is unavailable; sending is blocked."],
  ["L’opération du portefeuille a échoué de façon sécuritaire.", "The wallet operation failed safely."],
  ["Le stockage sécurisé Android est indisponible.", "Android secure storage is unavailable."],
  ["Le service Common Foundry est temporairement inaccessible.", "The Common Foundry service is temporarily unavailable."],
  ["Le serveur Common Foundry n’a pas encore validé les blocs nécessaires.", "The Common Foundry server has not yet validated the required blocks."],
  ["La réponse du service Common Foundry est invalide ou a été refusée.", "The Common Foundry service response is invalid or was refused."],
]);

export function localizedNativeMessage(
  message: string,
  language: Language,
  fallback: string,
): string {
  if (language === "fr") return message;
  return englishNativeMessages.get(message) ?? fallback;
}
