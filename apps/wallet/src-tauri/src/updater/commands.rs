//! The Tauri commands of the Updates card (UPDATER-DESIGN.md section 2.13,
//! as trimmed by TRIMMED-SCOPE.md: no policy, no soak, no downgrade gate).
//!
//! Each command answers at once. Checks and downloads run on the
//! updater's own worker; the card polls [`get_update_status`].

use std::thread;
use std::time::{Duration, Instant};

use cmfd_node::NodeClientError;
use tauri::{AppHandle, Manager, State};

use super::lifecycle::{ExitStarted, NodePhase};
use super::restart::{self, RelaunchTarget};
use super::{RUN_ANYWAY_CONFIRMATION, UpdateStatus, UpdaterState};
use crate::runtime::{RuntimeHandle, RuntimeState, startup_error};

/// How long "Restart to update" keeps trying while a status poll or a
/// short custody operation holds the operation lock.
const EXIT_RETRY: Duration = Duration::from_secs(1);
const EXIT_RETRY_POLL: Duration = Duration::from_millis(100);

#[tauri::command]
pub async fn get_update_status(
    updater: State<'_, UpdaterState>,
    runtime: State<'_, RuntimeState>,
) -> Result<UpdateStatus, NodeClientError> {
    Ok(updater.status(runtime.handle().is_held()))
}

#[tauri::command]
pub async fn set_update_automatic(
    updater: State<'_, UpdaterState>,
    runtime: State<'_, RuntimeState>,
    automatic: bool,
) -> Result<UpdateStatus, NodeClientError> {
    updater.set_automatic(automatic)?;
    Ok(updater.status(runtime.handle().is_held()))
}

#[tauri::command]
pub async fn check_for_updates(
    updater: State<'_, UpdaterState>,
    runtime: State<'_, RuntimeState>,
) -> Result<UpdateStatus, NodeClientError> {
    updater.check_now()?;
    Ok(updater.status(runtime.handle().is_held()))
}

/// `allow_copy`: the user agreed to copy the model bank when it cannot be
/// hard-linked.
#[tauri::command]
pub async fn download_update(
    updater: State<'_, UpdaterState>,
    runtime: State<'_, RuntimeState>,
    allow_copy: bool,
) -> Result<UpdateStatus, NodeClientError> {
    updater.download(allow_copy)?;
    Ok(updater.status(runtime.handle().is_held()))
}

/// Closes the wallet and starts the installed update on the same wallet
/// data. Refused while the wallet waits for Retry or Run anyway, when no
/// installed update would start ([`UpdaterState::restart_target`]: none,
/// or damaged), during a send, a backup, a restore, while the node starts,
/// while mining (unless `stop_mining`), while a send of this session may
/// not have reached the network, and while unconfirmed sends would be
/// dropped from memory (unless `accept_unconfirmed`).
#[tauri::command]
pub async fn restart_to_update(
    app: AppHandle,
    runtime: State<'_, RuntimeState>,
    stop_mining: bool,
    accept_unconfirmed: bool,
) -> Result<(), NodeClientError> {
    restart(app, runtime.handle(), stop_mining, accept_unconfirmed, None).await
}

/// "Retry" for a newer version that failed to start: restarts into it as
/// "Restart to update" does, with the same refusals and confirmations.
/// Its failed starts are forgotten only once the restart passed them. The
/// forwarder then starts the highest newer version it may start, which is
/// this one unless a higher one is installed too.
#[tauri::command]
pub async fn retry_update(
    app: AppHandle,
    runtime: State<'_, RuntimeState>,
    version: String,
    stop_mining: bool,
    accept_unconfirmed: bool,
) -> Result<(), NodeClientError> {
    let handle = runtime.handle();
    restart(app, handle, stop_mining, accept_unconfirmed, Some(version)).await
}

/// "Run anyway": after a newer version failed once it had opened the wallet
/// data, opens them with this older one. `confirm_text` must be
/// [`RUN_ANYWAY_CONFIRMATION`].
/// The choice is recorded in the failed version's state, so later launches
/// do not hold for that failure again.
#[tauri::command]
pub async fn run_older_anyway(
    app: AppHandle,
    runtime: State<'_, RuntimeState>,
    confirm_text: String,
) -> Result<UpdateStatus, NodeClientError> {
    check_run_anyway_confirmation(&confirm_text)?;
    let handle = runtime.handle();
    let worker = app.clone();
    run_blocking(move || {
        handle.run_held_start()?;
        worker.state::<UpdaterState>().record_run_anyway();
        Ok(())
    })
    .await?;
    Ok(app
        .state::<UpdaterState>()
        .status(runtime.handle().is_held()))
}

#[tauri::command]
pub async fn remove_old_versions(
    app: AppHandle,
    runtime: State<'_, RuntimeState>,
) -> Result<UpdateStatus, NodeClientError> {
    let worker = app.clone();
    run_blocking(move || worker.state::<UpdaterState>().remove_old_versions()).await?;
    Ok(app
        .state::<UpdaterState>()
        .status(runtime.handle().is_held()))
}

/// A held wallet offers Retry (which resets the failed version) and Run
/// anyway, not a second way into the version that failed.
fn refuse_while_held(handle: &RuntimeHandle) -> Result<(), NodeClientError> {
    if handle.is_held() {
        return Err(update_error(
            "update_held",
            "A newer version failed after it opened your wallet data. Choose Retry or Run anyway.",
            false,
        ));
    }
    Ok(())
}

fn check_run_anyway_confirmation(text: &str) -> Result<(), NodeClientError> {
    if text.trim().eq_ignore_ascii_case(RUN_ANYWAY_CONFIRMATION) {
        Ok(())
    } else {
        Err(update_error(
            "update_confirmation_required",
            format!(
                "Type \"{RUN_ANYWAY_CONFIRMATION}\" to run this older version on the wallet data."
            ),
            false,
        ))
    }
}

/// `retry`: the version whose failed starts are forgotten once the checks
/// passed, before the wallet commits to the exit. Without it, the installed
/// update is checked as the forwarder will check it, and refused while the
/// wallet is held.
async fn restart(
    app: AppHandle,
    handle: RuntimeHandle,
    stop_mining: bool,
    accept_unconfirmed: bool,
    retry: Option<String>,
) -> Result<(), NodeClientError> {
    let log_root = app.state::<UpdaterState>().log_root();
    // First, so that nothing is reset for a restart that cannot happen.
    let target = RelaunchTarget::of_this_process(log_root).map_err(|error| {
        update_error(
            "update_restart_unavailable",
            format!("The wallet cannot find its own program file: {error}"),
            true,
        )
    })?;
    let worker = app.clone();
    let exit = run_blocking(move || {
        let updater = worker.state::<UpdaterState>();
        if retry.is_none() {
            refuse_while_held(&handle)?;
            updater.restart_target()?;
        }
        let exit = prepare_restart(&handle, stop_mining, accept_unconfirmed, thread::sleep)?;
        // A failed reset drops `exit` uncommitted: the wallet stays usable.
        if let Some(version) = retry {
            updater.retry(&version)?;
        }
        Ok(exit)
    })
    .await?;
    if !restart::request_relaunch(target) {
        return Err(update_error(
            "update_restarting",
            "The wallet is restarting to update.",
            true,
        ));
    }
    // From here every send and custody operation is refused until the
    // process ends; the exit stops the node, mining and the updater.
    exit.commit();
    app.exit(0);
    Ok(())
}

/// The checks of "Restart to update", in order (design section 2.7): the
/// node is not starting (its open is not under the guard); the exit begins
/// once no send or custody operation runs (tried for [`EXIT_RETRY`]);
/// then, with every new one refused, mining and this session's sends.
/// Dropping the result without committing it leaves the wallet usable.
fn prepare_restart(
    handle: &RuntimeHandle,
    stop_mining: bool,
    accept_unconfirmed: bool,
    sleep: impl Fn(Duration),
) -> Result<ExitStarted, NodeClientError> {
    if handle.node_phase() == NodePhase::Starting {
        return Err(update_error(
            "update_busy",
            "The wallet is still starting. Restart to update once it is ready.",
            true,
        ));
    }
    let deadline = Instant::now() + EXIT_RETRY;
    let exit = loop {
        match handle.try_begin_exit() {
            Ok(exit) => break exit,
            Err(error) if error.code == "update_busy" && Instant::now() < deadline => {
                sleep(EXIT_RETRY_POLL);
            }
            Err(error) => return Err(error),
        }
    };
    if !stop_mining && handle.mining_active()? {
        return Err(update_error(
            "update_mining_active",
            "Mining will stop. After the restart, unlock the wallet and start mining again.",
            true,
        ));
    }
    let sends = handle.unrelayed_sends()?;
    if sends.maybe_not_relayed > 0 {
        return Err(update_error(
            "update_tx_pending",
            format!(
                "{} of your transactions may not have reached the network yet. Wait a minute, or until a peer is connected, then restart to update.",
                sends.maybe_not_relayed
            ),
            true,
        ));
    }
    if sends.unconfirmed > 0 && !accept_unconfirmed {
        return Err(update_error(
            "update_unconfirmed",
            format!(
                "{} of your transactions are unconfirmed. Unconfirmed transactions are kept in memory only (they are not saved across restarts); if one doesn't confirm, send it again.",
                sends.unconfirmed
            ),
            true,
        ));
    }
    Ok(exit)
}

async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, NodeClientError> + Send + 'static,
) -> Result<T, NodeClientError> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| {
            startup_error(
                "update_worker_failed",
                "The update worker stopped unexpectedly. Reopen the wallet.",
                true,
            )
        })?
}

fn update_error(
    code: &'static str,
    message: impl Into<String>,
    retryable: bool,
) -> NodeClientError {
    NodeClientError {
        code,
        status: 409,
        retryable,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn a_restart_is_refused_while_the_node_starts() {
        let handle = RuntimeState::starting_for_test().handle();
        let refused = prepare_restart(&handle, false, false, |_| panic!("waited")).unwrap_err();
        assert_eq!(refused.code, "update_busy");
        // The guard was never taken.
        assert!(handle.begin_node_operation().is_ok());
    }

    #[test]
    fn a_restart_of_a_locked_wallet_begins_the_exit() {
        let handle = RuntimeState::locked_for_test().handle();
        let exit = prepare_restart(&handle, false, false, |_| panic!("waited")).unwrap();
        assert_eq!(
            handle.begin_node_operation().unwrap_err().code,
            "update_restarting"
        );
        // Not committed: the wallet is usable again.
        drop(exit);
        assert!(handle.begin_node_operation().is_ok());
    }

    #[test]
    fn a_restart_keeps_trying_for_a_second_while_a_send_runs() {
        let handle = RuntimeState::locked_for_test().handle();
        let send = handle.begin_node_operation().unwrap();
        let waits = Cell::new(0);
        let refused = prepare_restart(&handle, true, true, |_| {
            waits.set(waits.get() + 1);
            thread::sleep(Duration::from_millis(50));
        })
        .unwrap_err();
        assert_eq!(refused.code, "update_busy");
        assert!(waits.get() >= 2);
        drop(send);
        // A refused restart leaves the wallet usable.
        assert!(handle.begin_node_operation().is_ok());
        // Once the send is over, the restart begins.
        let send = handle.begin_node_operation().unwrap();
        let ended = Cell::new(Some(send));
        let exit = prepare_restart(&handle, true, true, |_| drop(ended.take())).unwrap();
        drop(exit);
    }

    #[test]
    fn restart_to_update_is_refused_while_held() {
        let handle = RuntimeState::locked_for_test().handle();
        assert!(refuse_while_held(&handle).is_ok());
        handle.hold_for_test(startup_error(
            super::super::lifecycle::FALLBACK_HELD_CODE,
            "held",
            false,
        ));
        assert_eq!(refuse_while_held(&handle).unwrap_err().code, "update_held");
    }

    #[test]
    fn run_anyway_must_be_typed() {
        for typed in ["run anyway", "  Run Anyway ", "RUN ANYWAY"] {
            assert!(check_run_anyway_confirmation(typed).is_ok(), "{typed}");
        }
        for typed in ["", "yes", "run", "run  anyway"] {
            assert_eq!(
                check_run_anyway_confirmation(typed).unwrap_err().code,
                "update_confirmation_required",
                "{typed}"
            );
        }
    }
}
