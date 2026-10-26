// Request/response payloads are instantiated only by the Android binding.
// They remain compiled on desktop so the public bridge has one stable type set.
#![cfg_attr(desktop, allow(dead_code))]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EncodedWalletRequest {
    pub data_base64: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SaveDocumentRequest {
    pub data_base64: String,
    pub suggested_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EncodedWalletResponse {
    pub data_base64: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalWalletStatus {
    pub exists: bool,
    pub accessible: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentReceipt {
    pub uri: String,
    pub bytes_written: usize,
}
