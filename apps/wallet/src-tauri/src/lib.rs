mod commands;
mod cuda;
mod mining;
mod runtime;

use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{Manager, RunEvent};

use cmfd_node::COMPILED_NETWORK_PROFILE;
use runtime::RuntimeState;

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
        runtime::ProcessCommand::Run(config) => config,
    };

    let app = match tauri::Builder::default()
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
    fn rcnet_packaging_override_has_a_distinct_application_identity() {
        let devnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let rcnet: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.rcnet.conf.json")).unwrap();

        assert_eq!(devnet["identifier"], "org.commonfoundry.wallet.devnet");
        assert_eq!(rcnet["identifier"], "org.commonfoundry.wallet.rcnet1");
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
