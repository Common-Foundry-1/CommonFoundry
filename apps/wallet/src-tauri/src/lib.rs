mod commands;
mod cuda;
mod mining;
mod runtime;

use std::io::Write as _;

use base64::Engine as _;
use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{Manager, RunEvent};

use cmfd_node::{
    COMPILED_NETWORK_PROFILE, ProofProfile, canonical_network_info_json_with_v4_artifacts,
    production_v4_package_artifacts,
};
use runtime::RuntimeState;

const WALLET_RUNTIME_IDENTITY_SCHEMA: &str = "CMFD_WALLET_RUNTIME_IDENTITY_V1";
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
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the packaged wallet executable: {error}"))?;
    let artifacts = production_v4_package_artifacts(&executable)
        .map_err(|error| format!("cannot resolve packaged ProductionV4 artifacts: {error}"))?;
    let network_info = canonical_network_info_json_with_v4_artifacts(&artifacts)
        .map_err(|error| format!("cannot authenticate packaged ProductionV4 artifacts: {error}"))?;
    canonical_runtime_identity_json_for_network_info(&network_info)
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

    let app = match tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .setup(|app| {
            app.manage(RuntimeState::start(app, node_config));

            let mut window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or("the main wallet window is missing from tauri.conf.json")?
                .clone();
            window_config.title = COMPILED_NETWORK_PROFILE.wallet_window_title().to_owned();
            WebviewWindowBuilder::from_config(app, &window_config)?
                .on_navigation(allow_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_node_status,
            commands::get_peer_settings,
            commands::update_peer_settings,
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
            commands::choose_wallet_backup_path,
            commands::migrate_wallet_encryption,
            commands::restore_wallet,
        ])
        .build(tauri::generate_context!())
    {
        Ok(app) => app,
        Err(error) => {
            eprintln!("Common Foundry Wallet could not start: {error}");
            return 1;
        }
    };

    app.run_return(|app, event| {
        if matches!(event, RunEvent::Exit)
            && let Some(state) = app.try_state::<RuntimeState>()
        {
            state.stop_services();
        }
    })
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
