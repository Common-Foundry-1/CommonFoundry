use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_cmfd_android);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<CmfdAndroid<R>> {
    #[cfg(target_os = "android")]
    let handle =
        api.register_android_plugin("org.commonfoundry.wallet.android", "CmfdAndroidPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_cmfd_android)?;
    Ok(CmfdAndroid(handle))
}

/// Access to the cmfd-android APIs.
pub struct CmfdAndroid<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> CmfdAndroid<R> {
    pub fn biometric_status(&self) -> crate::Result<BiometricStatus> {
        self.0
            .run_mobile_plugin("biometricStatus", ())
            .map_err(Into::into)
    }

    pub fn enable_biometrics(&self, passphrase: &[u8], language: &str) -> crate::Result<()> {
        self.0
            .run_mobile_plugin(
                "enableBiometrics",
                BiometricRequest {
                    language,
                    data_base64: STANDARD.encode(passphrase),
                },
            )
            .map_err(Into::into)
    }

    pub fn unlock_biometrics(&self, language: &str) -> crate::Result<zeroize::Zeroizing<Vec<u8>>> {
        let response: BiometricResponse = self.0.run_mobile_plugin(
            "unlockBiometrics",
            BiometricRequest {
                language,
                data_base64: String::new(),
            },
        )?;
        let secret = zeroize::Zeroizing::new(
            STANDARD
                .decode(&response.data_base64)
                .map_err(|_| crate::Error::InvalidNativePayload)?,
        );
        if !(12..=4096).contains(&secret.len()) {
            return Err(crate::Error::InvalidNativePayload);
        }
        Ok(secret)
    }

    pub fn disable_biometrics(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin("disableBiometrics", ())
            .map_err(Into::into)
    }

    pub fn local_status(&self) -> crate::Result<LocalWalletStatus> {
        self.0
            .run_mobile_plugin("localStatus", ())
            .map_err(Into::into)
    }

    pub fn store_local(&self, encrypted_wallet: &[u8]) -> crate::Result<()> {
        let payload = EncodedWalletRequest {
            data_base64: STANDARD.encode(encrypted_wallet),
        };
        self.0
            .run_mobile_plugin::<()>("storeLocal", payload)
            .map_err(Into::into)
    }

    pub fn replace_inaccessible_local(&self, encrypted_wallet: &[u8]) -> crate::Result<()> {
        let payload = EncodedWalletRequest {
            data_base64: STANDARD.encode(encrypted_wallet),
        };
        self.0
            .run_mobile_plugin::<()>("replaceInaccessibleLocal", payload)
            .map_err(Into::into)
    }

    pub fn load_local(&self) -> crate::Result<Vec<u8>> {
        let response: EncodedWalletResponse = self.0.run_mobile_plugin("loadLocal", ())?;
        STANDARD
            .decode(response.data_base64)
            .map_err(|_| crate::Error::InvalidNativePayload)
    }

    pub fn save_document(
        &self,
        encrypted_wallet: &[u8],
        suggested_name: impl Into<String>,
    ) -> crate::Result<DocumentReceipt> {
        self.0
            .run_mobile_plugin(
                "saveDocument",
                SaveDocumentRequest {
                    data_base64: STANDARD.encode(encrypted_wallet),
                    suggested_name: suggested_name.into(),
                },
            )
            .map_err(Into::into)
    }

    pub fn open_document(&self) -> crate::Result<Vec<u8>> {
        let response: EncodedWalletResponse = self.0.run_mobile_plugin("openDocument", ())?;
        STANDARD
            .decode(response.data_base64)
            .map_err(|_| crate::Error::InvalidNativePayload)
    }
}
