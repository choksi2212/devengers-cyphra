// Key distribution server

pub mod server;
pub mod prekey_store;
pub mod revocation;

use cyphra_core::{DeviceId, Result};
use cyphra_protocol::PreKeyBundle;
use serde::{Deserialize, Serialize};

/// Upload prekey bundle request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadBundleRequest {
    pub bundle: PreKeyBundle,
}

/// Fetch prekey bundle request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchBundleRequest {
    pub device_id: DeviceId,
}

/// Fetch prekey bundle response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchBundleResponse {
    pub bundle: PreKeyBundle,
}
