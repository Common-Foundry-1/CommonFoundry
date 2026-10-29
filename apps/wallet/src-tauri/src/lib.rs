mod address;
mod commands;
mod cuda;
mod explorer;
mod mining;
mod runtime;
mod updater;

use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{Manager, RunEvent};

use cmfd_node::{
    COMPILED_NETWORK_PROFILE, ProofProfile, canonical_network_info_json_with_v4_artifacts,
    production_v4_package_artifacts,
};
use runtime::RuntimeState;
use updater::UpdaterState;

// An `updater-e2e` build reports other schemas, which the packaging and
// release-integrity scripts refuse: such a build can never be packaged as
// a release. The updater's own self-check reads only `package_version`.
#[cfg(not(feature = "updater-e2e"))]
const WALLET_RUNTIME_IDENTITY_SCHEMA: &str = "CMFD_WALLET_RUNTIME_IDENTITY_V1";
#[cfg(feature = "updater-e2e")]
const WALLET_RUNTIME_IDENTITY_SCHEMA: &str =
    "CMFD_WALLET_RUNTIME_IDENTITY_V1_UPDATER_E2E_TEST_BUILD_NEVER_RELEASE";
#[cfg(all(any(feature = "production-v4", test), not(feature = "updater-e2e")))]
const WALLET_PRELAUNCH_IDENTITY_SCHEMA: &str = "CMFD_WALLET_PRELAUNCH_IDENTITY_V1";
#[cfg(all(any(feature = "production-v4", test), feature = "updater-e2e"))]
const WALLET_PRELAUNCH_IDENTITY_SCHEMA: &str =
    "CMFD_WALLET_PRELAUNCH_IDENTITY_V1_UPDATER_E2E_TEST_BUILD_NEVER_RELEASE";
const WALLET_RUNTIME_ROLE: &str = "common-foundry-wallet";

#[derive(serde::Serialize)]
struct WalletRuntimeIdentity<'a> {
    // This field order is lexicographic. The compact encoding and trailing LF
    // are part of the release-integrity interface.
    network_info_base64: String,
    package_version: &'a str,
    role: &'static str,
    schema: &'static str,
}

fn canonical_runtime_identity_json() -> Result<Vec<u8>, String> {
    if COMPILED_NETWORK_PROFILE.proof != ProofProfile::ProductionV4 {
        return Err("runtime identity is available only in a ProductionV4 wallet build".to_owned());
    }
    #[cfg(feature = "production-v4")]
    if COMPILED_NETWORK_PROFILE.kind == cmfd_node::NetworkProfileKind::Mainnet {
        let info = cmfd_node::mainnet_runtime::canonical_mainnet_launch_info_json()
            .map_err(|error| format!("cannot authenticate mainnet launch plan: {error}"))?;
        return canonical_prelaunch_identity_json(&info);
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the packaged wallet executable: {error}"))?;
    let artifacts = production_v4_package_artifacts(&executable)
        .map_err(|error| format!("cannot resolve packaged ProductionV4 artifacts: {error}"))?;
    let network_info = canonical_network_info_json_with_v4_artifacts(&artifacts)
        .map_err(|error| format!("cannot authenticate packaged ProductionV4 artifacts: {error}"))?;
    canonical_runtime_identity_json_for_network_info(&network_info)
}

#[cfg(any(feature = "production-v4", test))]
fn canonical_prelaunch_identity_json(launch_info: &[u8]) -> Result<Vec<u8>, String> {
    // Separate schema: a prelaunch plan is not an activated network identity.
    let mut encoded = serde_json::to_vec(&serde_json::json!({
        "schema": WALLET_PRELAUNCH_IDENTITY_SCHEMA,
        "role": WALLET_RUNTIME_ROLE,
        "package_version": env!("CARGO_PKG_VERSION"),
        "launch_info_base64": base64::engine::general_purpose::STANDARD.encode(launch_info),
    }))
    .map_err(|error| error.to_string())?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn canonical_runtime_identity_json_for_network_info(
    network_info: &[u8],
) -> Result<Vec<u8>, String> {
    let identity = WalletRuntimeIdentity {
        network_info_base64: base64::engine::general_purpose::STANDARD.encode(network_info),
        package_version: env!("CARGO_PKG_VERSION"),
        role: WALLET_RUNTIME_ROLE,
        schema: WALLET_RUNTIME_IDENTITY_SCHEMA,
    };
    let mut encoded = serde_json::to_vec(&identity)
        .map_err(|error| format!("cannot encode the wallet runtime identity: {error}"))?;
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn run() -> i32 {
    // Before anything else, on the raw arguments: a newer installed version
    // runs instead of this one, and this one runs only if none could.
    let fallback = match updater::forward::at_launch() {
        updater::forward::Launch::Exit(code) => return code,
        updater::forward::Launch::RunHere(fallback) => fallback,
    };
    let command = match runtime::parse_command() {
        Ok(command) => command,
        Err(error) => {
            eprintln!("Common Foundry Wallet: {error}");
            eprintln!("Try --help for supported arguments.");
            return 2;
        }
    };

    let node_config = match command {
        runtime::ProcessCommand::Help => {
            println!("{}", runtime::command_help_text());
            return 0;
        }
        runtime::ProcessCommand::Version => {
            println!(env!("CARGO_PKG_VERSION"));
            return 0;
        }
        runtime::ProcessCommand::RuntimeIdentity => {
            let identity = match canonical_runtime_identity_json() {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("Common Foundry Wallet: {error}");
                    return 1;
                }
            };
            if let Err(error) = std::io::stdout().lock().write_all(&identity) {
                eprintln!("Common Foundry Wallet: cannot write runtime identity: {error}");
                return 1;
            }
            return 0;
        }
        runtime::ProcessCommand::Run(config) => *config,
    };
    // A start made by "Restart to update" waits for the closing wallet.
    if let Err(code) = updater::restart::wait_for_handoff(fallback.is_some()) {
        return code;
    }

    let webview_data_directory = node_config.webview_data_directory();
    let app = match tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .setup(move |app| {
            // A newer version failed after it had opened the wallet data:
            // this one opens them only once the user chooses.
            let held = fallback
                .as_ref()
                .filter(|fallback| fallback.after_data)
                .map(|fallback| {
                    updater::lifecycle::fallback_held_error(fallback, env!("CARGO_PKG_VERSION"))
                });
            app.manage(RuntimeState::start(app, node_config, held));
            let runtime = app.state::<RuntimeState>().handle();
            app.manage(UpdaterState::start(
                runtime.data_dir().map(Path::to_path_buf),
                runtime.no_auto_update(),
                fallback,
            ));

            let mut window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or("the main wallet window is missing from tauri.conf.json")?
                .clone();
            window_config.title = COMPILED_NETWORK_PROFILE.wallet_window_title().to_owned();
            #[cfg(feature = "updater-e2e")]
            window_config
                .title
                .push_str(" [UPDATER TEST BUILD, NOT A RELEASE]");
            let mut window = WebviewWindowBuilder::from_config(app, &window_config)?;
            if let Some(directory) = webview_data_directory {
                window = window.data_directory(directory);
            }
            window
                .on_navigation(allow_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
            // An updated version that fails to start ends here, so its
            // forwarder runs the previous one.
            let exit = app.handle().clone();
            runtime.spawn_start_watch(move |reason| {
                if updater::lifecycle::end_failed_start(&reason) {
                    exit.exit(updater::restart::START_FAILED_EXIT_CODE);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_node_status,
            commands::get_peer_settings,
            commands::update_peer_settings,
            commands::clear_failed_peers,
            commands::open_transaction_in_explorer,
            commands::get_wallet_snapshot,
            commands::get_mempool_snapshot,
            commands::send_wallet_transaction,
            commands::consolidate_wallet,
            commands::mine_devnet_block,
            commands::get_mining_status,
            commands::start_mining,
            commands::stop_mining,
            commands::get_wallet_custody_status,
            commands::unlock_wallet,
            commands::lock_wallet,
            commands::backup_wallet,
            commands::create_wallet,
            commands::choose_wallet_backup_path,
            commands::migrate_wallet_encryption,
            commands::restore_wallet,
            commands::resync_chain,
            updater::commands::get_update_status,
            updater::commands::set_update_automatic,
            updater::commands::check_for_updates,
            updater::commands::download_update,
            updater::commands::restart_to_update,
            updater::commands::retry_update,
            updater::commands::run_older_anyway,
            updater::commands::remove_old_versions,
        ])
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(error) => {
            eprintln!("Common Foundry Wallet could not start: {error}");
            return 1;
        }
    };

    let code = app.run_return(|app, event| {
        if matches!(event, RunEvent::Exit) {
            if let Some(state) = app.try_state::<RuntimeState>() {
                state.stop_services();
            }
            if let Some(updater) = app.try_state::<UpdaterState>() {
                updater.stop();
            }
        }
    });
    // "Restart to update": the relaunch starts once this wallet released
    // its data and the single-instance lock.
    updater::restart::relaunch_if_requested();
    updater::restart::exit_code(code)
}

fn allow_navigation(url: &tauri::Url) -> bool {
    let bundled = (url.scheme() == "tauri" && url.host_str() == Some("localhost"))
        || ((url.scheme() == "http" || url.scheme() == "https")
            && url.host_str() == Some("tauri.localhost"));
    let development = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(5173);
    bundled || development
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelaunch_identity_is_distinct_from_activated_network_identity() {
        let info = b"{\"format\":\"commonfoundry-mainnet-launch-info\"}\n";
        let bytes = canonical_prelaunch_identity_json(info).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema"], WALLET_PRELAUNCH_IDENTITY_SCHEMA);
        assert_eq!(value["role"], WALLET_RUNTIME_ROLE);
        assert!(value.get("network_info_base64").is_none());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(value["launch_info_base64"].as_str().unwrap())
                .unwrap(),
            info
        );
        let mut canonical = serde_json::to_vec(&value).unwrap();
        canonical.push(b'\n');
        assert_eq!(bytes, canonical);
    }

    /// The schemas the packaging and release-integrity scripts accept
    /// (`scripts/package_mainnet.py`, `scripts/verify_mainnet_ci_identities.py`),
    /// which only a build without `updater-e2e` reports.
    #[test]
    fn only_a_build_without_updater_e2e_reports_the_release_identity_schemas() {
        let release = (
            WALLET_PRELAUNCH_IDENTITY_SCHEMA == "CMFD_WALLET_PRELAUNCH_IDENTITY_V1",
            WALLET_RUNTIME_IDENTITY_SCHEMA == "CMFD_WALLET_RUNTIME_IDENTITY_V1",
        );
        assert_eq!(
            release,
            (
                !cfg!(feature = "updater-e2e"),
                !cfg!(feature = "updater-e2e")
            )
        );
        assert_eq!(
            updater::BUILD_IDENTITY == "release",
            !cfg!(feature = "updater-e2e")
        );
    }

    #[test]
    fn runtime_identity_encoding_is_canonical_and_binds_network_bytes() {
        let network_info = b"{\"format\":\"commonfoundry-network-info\"}\n";
        let encoded = canonical_runtime_identity_json_for_network_info(network_info).unwrap();
        assert!(encoded.ends_with(b"\n"));
        assert!(!encoded.contains(&b'\r'));

        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["schema"], WALLET_RUNTIME_IDENTITY_SCHEMA);
        assert_eq!(value["role"], WALLET_RUNTIME_ROLE);
        assert_eq!(value["package_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(value["network_info_base64"].as_str().unwrap())
                .unwrap(),
            network_info
        );
        let mut canonical = serde_json::to_vec(&value).unwrap();
        canonical.push(b'\n');
        assert_eq!(encoded, canonical);
    }

    #[test]
    fn network_packaging_overrides_have_distinct_application_identities() {
        let devnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let production_v3_testnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.production-v3-testnet.conf.json")).unwrap();
        let production_v4_testnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.production-v4-testnet.conf.json")).unwrap();
        let rcnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.rcnet.conf.json")).unwrap();

        assert_eq!(devnet["identifier"], "org.commonfoundry.wallet.devnet");
        assert_eq!(
            production_v3_testnet["identifier"],
            "org.commonfoundry.wallet.productionv3testnet1"
        );
        assert_eq!(
            production_v4_testnet["identifier"],
            "org.commonfoundry.wallet.productionv4testnet1"
        );
        assert_eq!(rcnet["identifier"], "org.commonfoundry.wallet.rcnet1");
        assert_ne!(devnet["identifier"], production_v3_testnet["identifier"]);
        assert_ne!(devnet["productName"], production_v3_testnet["productName"]);
        assert_ne!(devnet["identifier"], production_v4_testnet["identifier"]);
        assert_ne!(devnet["productName"], production_v4_testnet["productName"]);
        assert_ne!(
            production_v3_testnet["identifier"],
            production_v4_testnet["identifier"]
        );
        assert_ne!(
            production_v3_testnet["productName"],
            production_v4_testnet["productName"]
        );
        assert_ne!(production_v3_testnet["identifier"], rcnet["identifier"]);
        assert_ne!(production_v3_testnet["productName"], rcnet["productName"]);
        assert_ne!(production_v4_testnet["identifier"], rcnet["identifier"]);
        assert_ne!(production_v4_testnet["productName"], rcnet["productName"]);
        assert_ne!(devnet["identifier"], rcnet["identifier"]);
        assert_ne!(devnet["productName"], rcnet["productName"]);
    }

    #[test]
    fn navigation_is_limited_to_bundled_and_exact_development_origins() {
        assert!(allow_navigation(&"tauri://localhost".parse().unwrap()));
        assert!(allow_navigation(
            &"https://tauri.localhost".parse().unwrap()
        ));
        if cfg!(debug_assertions) {
            assert!(allow_navigation(&"http://127.0.0.1:5173".parse().unwrap()));
        }
        assert!(!allow_navigation(&"https://example.com".parse().unwrap()));
        assert!(!allow_navigation(
            &"http://127.0.0.1:18443".parse().unwrap()
        ));
        assert!(!allow_navigation(&"http://localhost:5173".parse().unwrap()));
    }
}
