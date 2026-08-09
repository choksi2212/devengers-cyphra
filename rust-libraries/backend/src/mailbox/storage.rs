// Message storage for mailbox server

use cyphra_core::{MessageId, Result, Error};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

/// In-memory message store (replace with persistent storage)
pub struct MessageStore {
    messages: Arc<RwLock<HashMap<MessageId, Vec<u8>>>>,
}

impl MessageStore {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

static mut GLOBAL_STORE: Option<MessageStore> = None;

fn get_store() -> &'static MessageStore {
    unsafe {
        GLOBAL_STORE.get_or_insert_with(|| MessageStore::new())
    }
}

/// Store encrypted message blob
pub async fn store_encrypted_blob(msg_id: MessageId, ciphertext: &[u8]) -> Result<()> {
    let store = get_store();
    let mut messages = store.messages.write().await;
    messages.insert(msg_id, ciphertext.to_vec());
    Ok(())
}

/// Retrieve encrypted message blob
pub async fn retrieve_encrypted_blob(msg_id: MessageId) -> Result<Vec<u8>> {
    let store = get_store();
    let messages = store.messages.read().await;
    messages.get(&msg_id)
        .cloned()
        .ok_or(Error::MessageNotFound)
}

/// Delete encrypted message blob
pub async fn delete_encrypted_blob(msg_id: MessageId) -> Result<()> {
    let store = get_store();
    let mut messages = store.messages.write().await;
    messages.remove(&msg_id)
        .ok_or(Error::MessageNotFound)?;
    Ok(())
}
