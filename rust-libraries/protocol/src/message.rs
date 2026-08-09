// Message format and serialization

use serde::{Deserialize, Serialize};
use cyphra_core::{MessageId, DeviceId, Result};

/// Message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub sender: DeviceId,
    pub recipient: DeviceId,
    pub timestamp: u64,
    pub content: MessageContent,
}

/// Message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Image(Vec<u8>),
    File { name: String, data: Vec<u8> },
    Voice(Vec<u8>),
    Video(Vec<u8>),
}

impl Message {
    pub fn new_text(sender: DeviceId, recipient: DeviceId, text: String) -> Self {
        let mut id_bytes = [0u8; 32];
        getrandom::getrandom(&mut id_bytes).unwrap();
        
        Self {
            id: MessageId(id_bytes),
            sender,
            recipient,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            content: MessageContent::Text(text),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| cyphra_core::Error::SerializationError(e.to_string()))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| cyphra_core::Error::SerializationError(e.to_string()))
    }
}
