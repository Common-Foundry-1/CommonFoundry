use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<CmfdAndroid<R>> {
    Ok(CmfdAndroid(app.clone()))
}

/// Access to the cmfd-android APIs.
pub struct CmfdAndroid<R: Runtime>(AppHandle<R>);

impl<R: Runtime> CmfdAndroid<R> {
    pub fn biometric_status(&self) -> crate::Result<BiometricStatus> {
        Ok(BiometricStatus {
            available: false,
            enabled: false,
        })
    }

    pub fn enable_biometrics(&self, _passphrase: &[u8], _language: &str) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn unlock_biometrics(&self, _language: &str) -> crate::Result<zeroize::Zeroizing<Vec<u8>>> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn disable_biometrics(&self) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn local_status(&self) -> crate::Result<LocalWalletStatus> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn store_local(&self, _encrypted_wallet: &[u8]) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn replace_inaccessible_local(&self, _encrypted_wallet: &[u8]) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn load_local(&self) -> crate::Result<Vec<u8>> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn save_document(
        &self,
        _encrypted_wallet: &[u8],
        _suggested_name: impl Into<String>,
    ) -> crate::Result<DocumentReceipt> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub fn open_document(&self) -> crate::Result<Vec<u8>> {
        Err(crate::Error::UnsupportedPlatform)
    }
}
