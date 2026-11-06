use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::CmfdAndroid;
#[cfg(mobile)]
use mobile::CmfdAndroid;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the cmfd-android APIs.
pub trait CmfdAndroidExt<R: Runtime> {
    fn cmfd_android(&self) -> &CmfdAndroid<R>;
}

impl<R: Runtime, T: Manager<R>> crate::CmfdAndroidExt<R> for T {
    fn cmfd_android(&self) -> &CmfdAndroid<R> {
        self.state::<CmfdAndroid<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("cmfd-android")
        .setup(|app, api| {
            #[cfg(mobile)]
            let cmfd_android = mobile::init(app, api)?;
            #[cfg(desktop)]
            let cmfd_android = desktop::init(app, api)?;
            app.manage(cmfd_android);
            Ok(())
        })
        .build()
}
