//! Mainnet preparation never retains a signing key or grants node authority.
use std::sync::{Arc, Mutex, atomic::AtomicBool};
use std::thread::JoinHandle;

use cmfd_node::NodeClientError;

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WalletLaunchStatus {
    pub mining_start_utc: &'static str,
    pub ready: bool,
    pub error: Option<String>,
}

#[derive(Default)]
pub(super) struct LaunchPreparation {
    error: Arc<Mutex<Option<String>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl LaunchPreparation {
    pub(super) fn start(cancel: Arc<AtomicBool>) -> Self {
        let preparation = Self::default();
        #[cfg(feature = "production-v4")]
        if cmfd_node::COMPILED_NETWORK_PROFILE.kind == cmfd_node::NetworkProfileKind::Mainnet {
            let error_slot = Arc::clone(&preparation.error);
            let result = std::thread::Builder::new()
                .name("cmfd-wallet-launch".into())
                .spawn(move || {
                    let result = (|| -> Result<(), String> {
                        let identity =
                            cmfd_node::mainnet_runtime::canonical_mainnet_launch_info_json()
                                .map_err(|error| error.to_string())?;
                        let executable =
                            std::env::current_exe().map_err(|error| error.to_string())?;
                        let package = executable.parent().ok_or("Package directory is absent")?;
                        cmfd_launch::acquire::acquire_for_package(package, &identity, true, &cancel)
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    })();
                    if let Err(error) = result
                        && let Ok(mut slot) = error_slot.lock()
                    {
                        *slot = Some(error);
                    }
                });
            match result {
                Ok(worker) => {
                    *preparation.worker.lock().expect("new launch worker mutex") = Some(worker)
                }
                Err(_) => {
                    *preparation.error.lock().expect("new launch error mutex") =
                        Some("Launch preparation could not start. Reopen the wallet.".into())
                }
            }
        }
        #[cfg(not(feature = "production-v4"))]
        let _ = cancel;
        preparation
    }

    pub(super) fn status(&self) -> Result<Option<WalletLaunchStatus>, NodeClientError> {
        #[cfg(feature = "production-v4")]
        if cmfd_node::COMPILED_NETWORK_PROFILE.kind == cmfd_node::NetworkProfileKind::Mainnet {
            // Even offline key creation requires this package's authenticated plan.
            cmfd_node::mainnet_runtime::canonical_mainnet_launch_info_json()
                .map_err(|error| error.client_error())?;
            let ready = match cmfd_node::mainnet_runtime::ensure_compiled_launch_ready() {
                Ok(()) => true,
                Err(cmfd_node::NodeError::MainnetLaunchRequired) => false,
                Err(error) => return Err(error.client_error()),
            };
            return Ok(Some(WalletLaunchStatus {
                mining_start_utc: cmfd_launch::MAINNET_LAUNCH_UTC,
                ready,
                error: self
                    .error
                    .lock()
                    .map_err(|_| super::runtime_state_error())?
                    .clone(),
            }));
        }
        // Read the slot in non-mainnet builds too, keeping the same state layout.
        let _ = &self.error;
        Ok(None)
    }

    pub(super) fn stop(&self) {
        if let Ok(mut slot) = self.worker.lock()
            && let Some(worker) = slot.take()
        {
            let _ = worker.join();
        }
    }
}
