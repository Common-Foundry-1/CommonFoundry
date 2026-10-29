//! Opens a wallet transaction on the public block explorer in the system
//! browser. The wallet window itself never leaves the bundled app (see
//! `allow_navigation`), so the page address is built here from a checked
//! transaction id and handed to the operating system.

use cmfd_node::{COMPILED_NETWORK_PROFILE, NetworkProfileKind, NodeClientError};

const MAINNET_EXPLORER: &str = "https://explorer.commonfoundry.ai";

/// The explorer page of `txid` on this build's network.
pub(crate) fn transaction_url(txid: &str) -> Result<String, NodeClientError> {
    transaction_url_for(COMPILED_NETWORK_PROFILE.kind, txid)
}

/// Only Mainnet has a public explorer. The id must be 64 hex digits, so the
/// address can only ever name an explorer transaction page.
fn transaction_url_for(network: NetworkProfileKind, txid: &str) -> Result<String, NodeClientError> {
    if network != NetworkProfileKind::Mainnet {
        return Err(NodeClientError {
            code: "explorer_unavailable",
            status: 501,
            retryable: false,
            message: "The block explorer shows Mainnet transactions only.".to_owned(),
        });
    }
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NodeClientError {
            code: "invalid_transaction_id",
            status: 400,
            retryable: false,
            message: "invalid transaction id: expected 64 hex digits".to_owned(),
        });
    }
    Ok(format!(
        "{MAINNET_EXPLORER}/tx/{}",
        txid.to_ascii_lowercase()
    ))
}

/// Hands `url` to the default browser.
pub(crate) fn open_in_browser(url: &str) -> Result<(), NodeClientError> {
    launch(url).map_err(|error| NodeClientError {
        code: "explorer_open_failed",
        status: 500,
        retryable: true,
        message: format!("The browser could not be opened: {error}"),
    })
}

#[cfg(windows)]
fn launch(url: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let wide = |text: &str| {
        std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<u16>>()
    };
    let operation = wide("open");
    let file = wide(url);
    // SAFETY: both strings are NUL-terminated and live for the whole call;
    // the window, parameters and directory may be null.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Values above 32 mean the browser was started.
    if result as usize > 32 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn launch(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Some desktops keep xdg-open running while the browser starts.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_transactions_open_on_the_explorer() {
        let txid = "Ab".repeat(32);
        assert_eq!(
            transaction_url_for(NetworkProfileKind::Mainnet, &txid).unwrap(),
            format!("https://explorer.commonfoundry.ai/tx/{}", "ab".repeat(32))
        );
    }

    #[test]
    fn only_a_transaction_id_reaches_the_address() {
        for txid in [
            String::new(),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("{}zz", "ab".repeat(31)),
            format!("{}/x", "ab".repeat(31)),
            format!("{}é", "a".repeat(62)),
        ] {
            let error = transaction_url_for(NetworkProfileKind::Mainnet, &txid).unwrap_err();
            assert_eq!(error.code, "invalid_transaction_id", "{txid}");
            assert_eq!(error.status, 400);
        }
    }

    #[test]
    fn other_networks_have_no_explorer() {
        for network in [
            NetworkProfileKind::Devnet,
            NetworkProfileKind::ProductionV3Testnet,
            NetworkProfileKind::ProductionV4Testnet,
            NetworkProfileKind::Rcnet,
        ] {
            let error = transaction_url_for(network, &"ab".repeat(32)).unwrap_err();
            assert_eq!(error.code, "explorer_unavailable");
        }
    }
}
