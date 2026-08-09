// Mailbox server for store-and-forward messaging

pub mod server;
pub mod storage;

use cyphra_core::{MessageId, DeviceId, Result, Error};
use serde::{Deserialize, Serialize};

/// Upload request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequest {
    pub token: crate::authentication::BlindToken,
    pub ciphertext: Vec<u8>,
    pub recipient_push_token: Option<String>,
}

/// Upload response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub msg_id: MessageId,
}

/// Download request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequest {
    pub token: crate::authentication::BlindToken,
    pub msg_id: MessageId,
}

/// Download response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub ciphertext: Vec<u8>,
}
