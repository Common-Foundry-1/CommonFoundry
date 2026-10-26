import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { QRCodeSVG } from "qrcode.react";
import appPackage from "../package.json";
import commonFoundryMark from "./assets/common-foundry-mark.png";
import {
  Format,
  checkPermissions,
  requestPermissions,
  scan,
} from "@tauri-apps/plugin-barcode-scanner";

import {
  createWallet,
  confirmAndBroadcastPayment,
  exportWallet,
  getPendingPayments,
  getSendAvailability,
  getWalletOverview,
  getWalletStatus,
  lockWallet,
  preparePayment,
  reconcilePendingPayments,
  restoreWallet,
  unlockWallet,
  type PaymentSummary,
  type HistoryEntry,
  type PendingPayment,
  type SendAvailability,
  type WalletOverview,
  type WalletStatus,
} from "./native";
import {
  I18nProvider,
  localizedNativeMessage,
  useI18n,
  type LanguagePreference,
  type ThemePreference,
  type TranslationKey,
} from "./i18n";

type LoadState =
  | { kind: "loading" }
  | { kind: "error" }
  | { kind: "ready"; wallet: WalletStatus };

type WalletView = "overview" | "receive" | "send" | "backup";

type HistoryDirection = "incoming" | "outgoing" | "internal" | "pending" | "unknown";

function historyDirection(entry: HistoryEntry): HistoryDirection {
  const kind = entry.kind.trim().toLowerCase();
  if (["received", "receive", "reward", "coinbase", "mined"].includes(kind)) {
    return "incoming";
  }
  if (["sent", "send", "spent", "outgoing", "mixed"].includes(kind)) {
    return "outgoing";
  }
  if (["self", "internal"].includes(kind)) return "internal";
  if (["pending", "mempool"].includes(kind)) return "pending";
  return "unknown";
}

function historyLabelKey(direction: Exclude<HistoryDirection, "incoming">): TranslationKey {
  switch (direction) {
    case "outgoing":
      return "historyOutgoing";
    case "internal":
      return "historyInternal";
    case "pending":
      return "historyPending";
    default:
      return "historyUnknown";
  }
}

function isRecognizedMainnetAddressShape(value: string): boolean {
  const address = value.trim();
  return /^cmfd1[02-9ac-hj-np-z]+$/.test(address) || /^[0-9a-f]{64}$/.test(address);
}

export function App() {
  return (
    <I18nProvider>
      <WalletApplication />
    </I18nProvider>
  );
}

function WalletApplication() {
  const { t, theme } = useI18n();
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [walletView, setWalletView] = useState<WalletView>("overview");

  useEffect(() => {
    let active = true;
    getWalletStatus()
      .then((wallet) => active && setState({ kind: "ready", wallet }))
      .catch(() =>
        active &&
        setState({ kind: "error" }),
      );
    return () => {
      active = false;
    };
  }, []);

  const updateWallet = useCallback(
    (wallet: WalletStatus) => setState({ kind: "ready", wallet }),
    [],
  );

  return (
    <main className="shell" data-theme={theme}>
      <header className="brand">
        <button
          type="button"
          className="brand-settings"
          aria-label={t("settings")}
          title={t("settings")}
          onClick={() => setSettingsOpen(true)}
        >
          <img className="brand-mark" src={commonFoundryMark} alt="" aria-hidden="true" />
          <span className="brand-copy">
            <strong>Common Foundry</strong>
            <small>{t("appSubtitle")}</small>
          </span>
          <span className="settings-glyph" aria-hidden="true">⚙</span>
        </button>
      </header>

      {state.kind === "loading" && <StatusCard text={t("openingWallet")} />}
      {state.kind === "error" && <StatusCard text={t("secureServiceUnavailable")} tone="error" />}
      {state.kind === "ready" && !state.wallet.configured && (
        <Onboarding onComplete={updateWallet} />
      )}
      {state.kind === "ready" && state.wallet.configured && !state.wallet.unlocked && (
        <Unlock wallet={state.wallet} onComplete={updateWallet} />
      )}
      {state.kind === "ready" && state.wallet.configured && state.wallet.unlocked && (
        <WalletHome
          wallet={state.wallet}
          onWalletChange={updateWallet}
          view={walletView}
          onViewChange={setWalletView}
        />
      )}
      {settingsOpen && (
        <SettingsPanel
          version={appPackage.version}
          backupAvailable={
            state.kind === "ready" && state.wallet.configured && state.wallet.unlocked
          }
          onOpenBackup={() => {
            setWalletView("backup");
            setSettingsOpen(false);
          }}
          onOpenNotices={async () => {
            if (state.kind === "ready" && state.wallet.unlocked) {
              const locked = await lockWallet();
              if (locked.unlocked) throw new Error("wallet did not lock");
              updateWallet(locked);
            }
            window.location.assign("/android-library-notices.html");
          }}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </main>
  );
}

function SettingsPanel({
  version,
  backupAvailable,
  onOpenBackup,
  onOpenNotices,
  onClose,
}: {
  version: string;
  backupAvailable: boolean;
  onOpenBackup: () => void;
  onOpenNotices: () => Promise<void>;
  onClose: () => void;
}) {
  const [noticesError, setNoticesError] = useState(false);
  const {
    t,
    languagePreference,
    setLanguagePreference,
    theme,
    setTheme,
  } = useI18n();

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const themeOption = (
    value: ThemePreference,
    label: string,
    description: string,
  ) => (
    <label className="preference-card">
      <input
        type="radio"
        name="theme"
        value={value}
        checked={theme === value}
        onChange={() => setTheme(value)}
      />
      <span><strong>{label}</strong><small>{description}</small></span>
    </label>
  );

  const languageOption = (value: LanguagePreference, label: string) => (
    <label className="preference-card compact-option">
      <input
        type="radio"
        name="language"
        value={value}
        checked={languagePreference === value}
        onChange={() => setLanguagePreference(value)}
      />
      <span><strong>{label}</strong></span>
    </label>
  );

  return (
    <div className="settings-backdrop">
      <section
        className="panel settings-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
      >
        <div className="settings-heading">
          <div>
            <p className="eyebrow">COMMON FOUNDRY</p>
            <h1 id="settings-title">{t("settingsTitle")}</h1>
          </div>
          <button type="button" className="small secondary" onClick={onClose}>
            {t("closeSettings")}
          </button>
        </div>

        <section className="settings-section" aria-labelledby="appearance-title">
          <h2 id="appearance-title">{t("appearance")}</h2>
          <div className="preference-grid">
            {themeOption("light", t("light"), t("lightDescription"))}
            {themeOption("dark", t("dark"), t("darkDescription"))}
          </div>
        </section>

        <section className="settings-section" aria-labelledby="language-title">
          <h2 id="language-title">{t("language")}</h2>
          <div className="preference-grid language-options">
            {languageOption("automatic", t("automatic"))}
            {languageOption("en", t("english"))}
            {languageOption("fr", t("french"))}
          </div>
          <p className="settings-help">{t("automaticDescription")}</p>
        </section>

        <section className="settings-section" aria-labelledby="wallet-settings-title">
          <h2 id="wallet-settings-title">{t("walletSection")}</h2>
          <button type="button" disabled={!backupAvailable} onClick={onOpenBackup}>
            {t("backupShortcut")}
          </button>
          <p className="settings-help">
            {backupAvailable ? t("backupShortcutHelp") : t("backupUnavailable")}
          </p>
        </section>

        <section className="settings-section about-section" aria-labelledby="about-title">
          <h2 id="about-title">{t("about")}</h2>
          <strong>{t("appName")}</strong>
          <span>{t("version", { version })}</span>
          <span>{t("network")}</span>
          <p>{t("openSource")}</p>
          <button
            type="button"
            className="notices-link"
            onClick={() => {
              setNoticesError(false);
              void onOpenNotices().catch(() => setNoticesError(true));
            }}
          >
            {t("licensesAndPrivacy")}
          </button>
          {noticesError && <p className="inline-error" role="alert">{t("noticesLockFailed")}</p>}
        </section>
      </section>
    </div>
  );
}

function Onboarding({ onComplete }: { onComplete: (wallet: WalletStatus) => void }) {
  const { t } = useI18n();
  const [flow, setFlow] = useState<"create" | "restore" | null>(null);
  return (
    <section className="panel hero" aria-labelledby="welcome-title">
      <p className="eyebrow">{t("mainnetEyebrow")}</p>
      <h1 id="welcome-title">{t("welcomeTitle")}</h1>
      <p>{t("welcomeBody")}</p>
      {flow === null && (
        <>
          <div className="actions" aria-label={t("walletActions")}>
            <button onClick={() => setFlow("create")}>{t("createWallet")}</button>
            <button className="secondary" onClick={() => setFlow("restore")}>
              {t("restoreBackup")}
            </button>
          </div>
          <p className="notice" role="note">{t("activationNotice")}</p>
        </>
      )}
      {flow === "create" && (
        <>
          <p className="safety-warning" role="note">{t("backupLossWarning")}</p>
          <PassphraseAction
            title={t("createAndBackup")}
            explanation={t("createExplanation")}
            confirmation
            submitLabel={t("chooseBackupLocation")}
            action={createWallet}
            onCancel={() => setFlow(null)}
            onComplete={onComplete}
          />
        </>
      )}
      {flow === "restore" && (
        <PassphraseAction
          title={t("restoreTitle")}
          explanation={t("restoreExplanation")}
          submitLabel={t("chooseBackup")}
          action={restoreWallet}
          onCancel={() => setFlow(null)}
          onComplete={onComplete}
        />
      )}
    </section>
  );
}

function Unlock({
  wallet,
  onComplete,
}: {
  wallet: WalletStatus;
  onComplete: (wallet: WalletStatus) => void;
}) {
  const { t } = useI18n();
  if (wallet.recoveryRequired) {
    return (
      <section className="panel hero compact">
        <p className="eyebrow">{t("recoveryRequired")}</p>
        <h1>{t("keystoreUnavailableTitle")}</h1>
        <p>{t("keystoreUnavailableBody")}</p>
        <PassphraseAction
          title={t("restoreOfficialBackup")}
          explanation={t("restoreOfficialExplanation")}
          submitLabel={t("chooseAuthenticateBackup")}
          action={restoreWallet}
          onComplete={onComplete}
        />
      </section>
    );
  }
  return (
    <section className="panel hero compact">
      <p className="eyebrow">{t("walletLocked")}</p>
      <h1>{t("unlockRequired")}</h1>
      <p>{t("unlockPrivacy")}</p>
      <PassphraseAction
        title={t("passphrase")}
        explanation={t("passphraseExplanation")}
        submitLabel={t("unlock")}
        action={unlockWallet}
        onComplete={onComplete}
      />
    </section>
  );
}

function PassphraseAction({
  title,
  explanation,
  submitLabel,
  confirmation = false,
  action,
  onComplete,
  onCancel,
}: {
  title: string;
  explanation: string;
  submitLabel: string;
  confirmation?: boolean;
  action: (passphrase: string) => Promise<WalletStatus>;
  onComplete: (wallet: WalletStatus) => void;
  onCancel?: () => void;
}) {
  const { t, language } = useI18n();
  const passphraseRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    let passphrase = passphraseRef.current?.value ?? "";
    const repeated = confirmationRef.current?.value ?? "";
    if (new TextEncoder().encode(passphrase).length < 12) {
      setError(t("passphraseMinimum"));
      return;
    }
    if (confirmation && passphrase !== repeated) {
      setError(t("passphraseMismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    if (passphraseRef.current) passphraseRef.current.value = "";
    if (confirmationRef.current) confirmationRef.current.value = "";
    try {
      const wallet = await action(passphrase);
      passphrase = "";
      onComplete(wallet);
    } catch (reason) {
      passphrase = "";
      setError(publicError(reason, language, t("genericFailure")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="secure-form" onSubmit={(event) => void submit(event)}>
      <h2>{title}</h2>
      <p className="form-help">{explanation}</p>
      <label>
        {t("passphrase")}
        <input ref={passphraseRef} type="password" autoComplete="off" minLength={12} required />
      </label>
      {confirmation && (
        <label>
          {t("confirmPassphrase")}
          <input ref={confirmationRef} type="password" autoComplete="off" minLength={12} required />
        </label>
      )}
      {error && <p className="inline-error" role="alert">{error}</p>}
      <div className="form-actions">
        <button type="submit" disabled={busy}>{busy ? t("secureProcessing") : submitLabel}</button>
        {onCancel && (
          <button type="button" className="secondary" disabled={busy} onClick={onCancel}>{t("back")}</button>
        )}
      </div>
    </form>
  );
}

function WalletHome({
  wallet,
  onWalletChange,
  view,
  onViewChange,
}: {
  wallet: WalletStatus;
  onWalletChange: (wallet: WalletStatus) => void;
  view: WalletView;
  onViewChange: (view: WalletView) => void;
}) {
  const { t, language } = useI18n();
  const [overview, setOverview] = useState<WalletOverview | null>(null);
  const [send, setSend] = useState<SendAvailability | null>(null);
  const [networkError, setNetworkError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    const lockOrRefresh = () => {
      if (document.visibilityState === "hidden") {
        void lockWallet().then(onWalletChange).catch(() => undefined);
      } else {
        void getWalletStatus().then(onWalletChange).catch(() => undefined);
      }
    };
    lockOrRefresh();
    document.addEventListener("visibilitychange", lockOrRefresh);
    return () => document.removeEventListener("visibilitychange", lockOrRefresh);
  }, [onWalletChange]);

  const refresh = async () => {
    setRefreshing(true);
    setNetworkError(null);
    const [overviewResult, sendResult] = await Promise.allSettled([
      getWalletOverview(),
      getSendAvailability(),
    ]);
    if (overviewResult.status === "fulfilled") {
      setOverview(overviewResult.value);
    } else {
      setNetworkError(publicError(overviewResult.reason, language, t("genericFailure")));
    }
    if (sendResult.status === "fulfilled") {
      setSend(sendResult.value);
    } else {
      setSend({
        available: false,
        message: publicError(sendResult.reason, language, t("genericFailure")),
        nextHeight: null,
        utxoCount: 0,
        spendableAtoms: null,
        feeAtoms: null,
        maximumAtoms: null,
      });
    }
    setRefreshing(false);
  };

  useEffect(() => {
    void refresh();
  }, []);

  if (!wallet.address) return <StatusCard text={t("identityUnavailable")} tone="error" />;

  return (
    <section className="wallet-shell" aria-labelledby="wallet-title">
      <div className="wallet-heading">
        <div>
          <p className="eyebrow">{wallet.networkName}</p>
          <h1 id="wallet-title">{t("walletTitle")}</h1>
        </div>
        <button
          className="small secondary"
          onClick={() => void lockWallet().then(onWalletChange)}
        >
          {t("lock")}
        </button>
      </div>

      <nav className="tabs" aria-label={t("walletSections")}>
        {(["overview", "receive", "send", "backup"] as const).map((item) => (
          <button
            key={item}
            className={view === item ? "active" : "secondary"}
            onClick={() => onViewChange(item)}
          >
            {{
              overview: t("overview"),
              receive: t("receive"),
              send: t("send"),
              backup: t("backup"),
            }[item]}
          </button>
        ))}
      </nav>

      {view === "overview" && (
        <OverviewPanel
          overview={overview}
          error={networkError}
          refreshing={refreshing}
          onRefresh={() => void refresh()}
        />
      )}
      {view === "receive" && <ReceivePanel address={wallet.address} />}
      {view === "send" && <SendPanel availability={send} />}
      {view === "backup" && <BackupPanel />}
    </section>
  );
}

function OverviewPanel({
  overview,
  error,
  refreshing,
  onRefresh,
}: {
  overview: WalletOverview | null;
  error: string | null;
  refreshing: boolean;
  onRefresh: () => void;
}) {
  const { t, language } = useI18n();
  return (
    <div className="panel wallet-content">
      <div className="section-heading">
        <h2>{t("realBalance")}</h2>
        <button className="small secondary" onClick={onRefresh} disabled={refreshing}>
          {refreshing ? t("refreshing") : t("refresh")}
        </button>
      </div>
      {error && <p className="inline-error" role="alert">{error} {t("staleData")}</p>}
      {!overview && !error && <p>{t("loadingMainnet")}</p>}
      {overview && (
        <>
          <div className="balances">
            <Balance label={t("available")} atoms={overview.spendableAtoms} primary />
            <Balance label={t("confirmed")} atoms={overview.confirmedAtoms} />
            <Balance label={t("immature")} atoms={overview.immatureAtoms} />
          </div>
          <p className="safety-warning" role="note">{t("backupLossWarning")}</p>
          <p className="notice">
            {t("acceptedHeight", {
              height: overview.acceptedHeight,
              validated: overview.validatedHeight ?? t("unavailable"),
            })}
            {overview.includesMempool ? t("mempoolIncluded") : t("mempoolExcluded")}
          </p>
          <h2>{t("recentTransactions")}</h2>
          {overview.history.length === 0 ? (
            <p>{t("noTransactions")}</p>
          ) : (
            <ul className="history">
              {overview.history.map((entry) => {
                const direction = historyDirection(entry);
                return (
                  <li key={`${entry.txid}:${entry.blockHeight}`}>
                    <div>
                      {direction === "incoming" ? (
                        <strong>+ {formatAtoms(entry.receivedAtoms)} CMFD</strong>
                      ) : (
                        <strong>{t(historyLabelKey(direction))}</strong>
                      )}
                      {direction !== "incoming" && (
                        <span>{t("historyAmountUnavailable")}</span>
                      )}
                      <span>{entry.confirmations === 1
                        ? t("oneConfirmation")
                        : t("manyConfirmations", { count: entry.confirmations })}</span>
                    </div>
                    <code>{shortHash(entry.txid)}</code>
                    <span>{formatTimestamp(entry.timestamp, language, t("dateUnavailable"))}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {overview.hasMoreHistory && <p className="notice">{t("olderHistory")}</p>}
        </>
      )}
    </div>
  );
}

function Balance({ label, atoms, primary = false }: { label: string; atoms: string; primary?: boolean }) {
  return (
    <div className={primary ? "balance primary" : "balance"}>
      <span>{label}</span>
      <strong>{formatAtoms(atoms)}</strong>
      <small>CMFD</small>
    </div>
  );
}

function ReceivePanel({ address }: { address: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="panel wallet-content receive">
      <p className="eyebrow">{t("receiveEyebrow")}</p>
      <h2>{t("mainnetAddress")}</h2>
      <div className="qr" aria-label={t("receiveQrLabel")}>
        <QRCodeSVG value={address} size={208} level="M" />
      </div>
      <p className="address">{address}</p>
      <button onClick={() => void copy()}>{copied ? t("addressCopied") : t("copyAddress")}</button>
      <p className="notice">{t("receiveQrNotice")}</p>
    </div>
  );
}

function SendPanel({ availability }: { availability: SendAvailability | null }) {
  const { t, language } = useI18n();
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [scanError, setScanError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<PaymentSummary | null>(null);
  const [pending, setPending] = useState<PendingPayment[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);

  const refreshPending = async (reconcile: boolean) => {
    try {
      setPending(await (reconcile ? reconcilePendingPayments() : getPendingPayments()));
      if (reconcile) setMessage(null);
    } catch (reason) {
      setError(publicError(reason, language, t("genericFailure")));
    }
  };

  useEffect(() => {
    void refreshPending(false);
  }, []);

  const scanRecipient = async () => {
    setScanError(null);
    try {
      let permission = await checkPermissions();
      if (permission !== "granted") permission = await requestPermissions();
      if (permission !== "granted") {
        setScanError(t("cameraPermissionRequired"));
        return;
      }
      const result = await scan({
        cameraDirection: "back",
        formats: [Format.QRCode],
        windowed: false,
      });
      if (!isRecognizedMainnetAddressShape(result.content)) {
        setScanError(t("invalidQr"));
        return;
      }
      setRecipient(result.content.trim());
      setPrepared(null);
    } catch {
      setScanError(t("scanCancelled"));
    }
  };

  const prepare = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    setConfirmed(false);
    try {
      setPrepared(await preparePayment(recipient.trim(), amount.trim()));
    } catch (reason) {
      setPrepared(null);
      setError(publicError(reason, language, t("genericFailure")));
    } finally {
      setBusy(false);
    }
  };

  const broadcast = async () => {
    if (!prepared || !confirmed) return;
    setBusy(true);
    setError(null);
    try {
      const outcome = await confirmAndBroadcastPayment(prepared.intent);
      setMessage(outcome.message);
      setPrepared(null);
      setConfirmed(false);
      setAmount("");
      await refreshPending(false);
    } catch (reason) {
      setError(publicError(reason, language, t("genericFailure")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel wallet-content">
      <p className="eyebrow">{t("sendEyebrow")}</p>
      <h2>{t("preparePayment")}</h2>
      <form className="secure-form" onSubmit={(event) => void prepare(event)}>
        <label>
          {t("recipientAddress")}
          <span className="field-with-button">
            <input
              type="text"
              inputMode="text"
              placeholder="cmfd1…"
              value={recipient}
              disabled={busy || prepared !== null}
              onChange={(event) => {
                setRecipient(event.target.value);
                setPrepared(null);
              }}
              required
            />
            <button
              type="button"
              className="secondary"
              disabled={busy || prepared !== null}
              onClick={() => void scanRecipient()}
            >
              {t("scan")}
            </button>
          </span>
        </label>
        <small className="qr-privacy-note">{t("qrPrivacyNote")}</small>
        <label>
          {t("amountCmfd")}
          <input
            type="text"
            inputMode="decimal"
            placeholder="0.00000000"
            value={amount}
            disabled={busy || prepared !== null}
            onChange={(event) => {
              setAmount(event.target.value);
              setPrepared(null);
            }}
            required
          />
        </label>
        <dl className="send-limits" aria-label={t("spendingInformation")}>
          <div>
            <dt>{t("availableBalance")}</dt>
            <dd>{availability?.spendableAtoms !== null && availability?.spendableAtoms !== undefined
              ? `${formatAtoms(availability.spendableAtoms)} CMFD`
              : t("unavailable")}</dd>
          </div>
          <div>
            <dt>{t("expectedNetworkFee")}</dt>
            <dd>{availability?.feeAtoms !== null && availability?.feeAtoms !== undefined
              ? `${formatAtoms(availability.feeAtoms)} CMFD`
              : t("unavailable")}</dd>
          </div>
          <div>
            <dt>{t("maximumSendable")}</dt>
            <dd>{availability?.maximumAtoms !== null && availability?.maximumAtoms !== undefined
              ? `${formatAtoms(availability.maximumAtoms)} CMFD`
              : t("unavailable")}</dd>
          </div>
        </dl>
        <button disabled={busy || prepared !== null || availability?.available !== true}>
          {busy ? t("verifying") : t("verifyUtxoFees")}
        </button>
      </form>
      {scanError && <p className="inline-error">{scanError}</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {message && <p className="notice" role="status">
        {localizedNativeMessage(message, language, t("genericFailure"))}
      </p>}
      {!availability && <p className="notice">{t("checkingUtxo")}</p>}
      {availability && !availability.available && (
        <p className="inline-error">
          {availability.message
            ? localizedNativeMessage(availability.message, language, t("genericFailure"))
            : t("utxoUnavailable")}
        </p>
      )}
      {availability?.available && (
        <>
          <p className="notice">
            {availability.utxoCount === 1
              ? t("gatewayRespondsOne")
              : t("gatewayRespondsMany", { count: availability.utxoCount })}
          </p>
          {availability.message && (
            <p className="safety-warning" role="note">
              {localizedNativeMessage(availability.message, language, t("genericFailure"))}
            </p>
          )}
        </>
      )}
      {prepared && (
        <div className="confirmation" aria-label={t("irreversibleConfirmation")}>
          <h3>{t("irreversibleConfirmation")}</h3>
          <dl>
            <div><dt>{t("recipientHex")}</dt><dd className="address">{prepared.recipientHex}</dd></div>
            {prepared.recipientBech32m && (
              <div><dt>{t("recipientBech32m")}</dt><dd className="address">{prepared.recipientBech32m}</dd></div>
            )}
            <div><dt>{t("amount")}</dt><dd>{formatAtoms(prepared.amountAtoms)} CMFD</dd></div>
            <div><dt>{t("expectedFee")}</dt><dd>{formatAtoms(prepared.feeAtoms)} CMFD</dd></div>
            <div><dt>{t("change")}</dt><dd>{formatAtoms(prepared.changeAtoms)} CMFD</dd></div>
            <div><dt>{t("selectedInputs")}</dt><dd>{prepared.selectedInputs}</dd></div>
          </dl>
          <label className="confirm-check">
            <input
              type="checkbox"
              checked={confirmed}
              disabled={busy}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            {t("broadcastAuthorization")}
          </label>
          <div className="form-actions">
            <button disabled={!confirmed || busy} onClick={() => void broadcast()}>
              {busy ? t("signingBroadcast") : t("signBroadcastOnce")}
            </button>
            <button
              className="secondary"
              disabled={busy}
              onClick={() => {
                setPrepared(null);
                setConfirmed(false);
              }}
            >
              {t("cancel")}
            </button>
          </div>
        </div>
      )}
      <div className="section-heading pending-heading">
        <h3>{t("trackedTransactions")}</h3>
        <button className="small secondary" disabled={busy} onClick={() => void refreshPending(true)}>
          {t("checkConfirmations")}
        </button>
      </div>
      {pending.length === 0 ? (
        <p>{t("noPending")}</p>
      ) : (
        <ul className="history">
          {pending.map((payment) => (
            <li key={payment.txid}>
              <div>
                <strong>- {formatAtoms(payment.amountAtoms)} CMFD</strong>
                <span>{pendingLabel(payment, t)}</span>
              </div>
              <code>{shortHash(payment.txid)}</code>
              <span>{formatTimestamp(payment.createdAt, language, t("dateUnavailable"))}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function BackupPanel() {
  const { t, language } = useI18n();
  const passphraseRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    let passphrase = passphraseRef.current?.value ?? "";
    if (new TextEncoder().encode(passphrase).length < 12) {
      setMessage(t("passphraseMinimum"));
      return;
    }
    if (passphraseRef.current) passphraseRef.current.value = "";
    setBusy(true);
    setMessage(null);
    try {
      await exportWallet(passphrase);
      passphrase = "";
      setMessage(t("exportSuccess"));
    } catch (reason) {
      passphrase = "";
      setMessage(publicError(reason, language, t("genericFailure")));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="panel wallet-content">
      <p className="eyebrow">{t("backupEyebrow")}</p>
      <h2>{t("exportOfficialCopy")}</h2>
      <p>{t("exportDescription")}</p>
      <p className="safety-warning" role="note">{t("backupLossWarning")}</p>
      <form className="secure-form" onSubmit={(event) => void submit(event)}>
        <label>
          {t("currentPassphrase")}
          <input ref={passphraseRef} type="password" autoComplete="off" minLength={12} required />
        </label>
        <button disabled={busy}>{busy ? t("exporting") : t("chooseLocation")}</button>
      </form>
      {message && <p className={message === t("exportSuccess") ? "success" : "inline-error"}>{message}</p>}
      <p className="notice">{t("keystoreNotIncluded")}</p>
    </div>
  );
}

function StatusCard({ text, tone = "normal" }: { text: string; tone?: "normal" | "error" }) {
  return <p className={`panel status ${tone}`}>{text}</p>;
}

function publicError(reason: unknown, language: "en" | "fr", fallback: string): string {
  if (typeof reason === "string" && reason.length > 0 && reason.length < 500) {
    return localizedNativeMessage(reason, language, fallback);
  }
  return fallback;
}

function formatAtoms(value: string): string {
  try {
    const atoms = BigInt(value);
    const whole = atoms / 100_000_000n;
    const fraction = (atoms % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
    return fraction ? `${whole}.${fraction}` : whole.toString();
  } catch {
    return "—";
  }
}

function shortHash(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function formatTimestamp(
  timestamp: number | null,
  language: "en" | "fr",
  unavailable: string,
): string {
  if (timestamp === null) return unavailable;
  return new Date(timestamp * 1000).toLocaleString(language === "fr" ? "fr-CA" : "en-CA");
}

function pendingLabel(payment: PendingPayment, t: ReturnType<typeof useI18n>["t"]): string {
  switch (payment.state) {
    case "broadcast_unknown":
      return t("pendingUnknown");
    case "accepted":
      return t("pendingAccepted");
    case "confirmed":
      return payment.confirmations === 1
        ? t("pendingConfirmedOne")
        : t("pendingConfirmedMany", { count: payment.confirmations });
    case "conflicted":
      return t("pendingConflicted");
    case "dropped":
      return t("pendingDropped");
  }
}
