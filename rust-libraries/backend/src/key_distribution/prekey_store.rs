// Prekey storage backend

use cyphra_core::{DeviceId, Result, Error};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

struct PreKeyStorage {
    identity_keys: Arc<RwLock<HashMap<DeviceId, Vec<u8>>>>,
    signed_prekeys: Arc<RwLock<HashMap<DeviceId, (Vec<u8>, Vec<u8>)>>>,
    one_time_prekeys: Arc<RwLock<HashMap<DeviceId, Vec<Vec<u8>>>>>,
}

impl PreKeyStorage {
    fn new() -> Self {
        Self {
            identity_keys: Arc::new(RwLock::new(HashMap::new())),
            signed_prekeys: Arc::new(RwLock::new(HashMap::new())),
            one_time_prekeys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

static mut GLOBAL_STORAGE: Option<PreKeyStorage> = None;

fn get_storage() -> &'static PreKeyStorage {
    unsafe {
        GLOBAL_STORAGE.get_or_insert_with(|| PreKeyStorage::new())
    }
}

/// Store identity key
pub async fn store_identity_key(device_id: DeviceId, key: Vec<u8>) -> Result<()> {
    let storage = get_storage();
    let mut keys = storage.identity_keys.write().await;
    keys.insert(device_id, key);
    Ok(())
}

/// Get identity key
pub async fn get_identity_key(device_id: DeviceId) -> Result<Vec<u8>> {
    let storage = get_storage();
    let keys = storage.identity_keys.read().await;
    keys.get(&device_id)
        .cloned()
        .ok_or(Error::DeviceNotFound)
}

/// Store signed prekey
pub async fn store_signed_prekey(
    device_id: DeviceId,
    prekey: Vec<u8>,
    signature: Vec<u8>,
) -> Result<()> {
    let storage = get_storage();
    let mut prekeys = storage.signed_prekeys.write().await;
    prekeys.insert(device_id, (prekey, signature));
    Ok(())
}

/// Get signed prekey
pub async fn get_signed_prekey(device_id: DeviceId) -> Result<(Vec<u8>, Vec<u8>)> {
    let storage = get_storage();
    let prekeys = storage.signed_prekeys.read().await;
    prekeys.get(&device_id)
        .cloned()
        .ok_or(Error::DeviceNotFound)
}

/// Store one-time prekey
pub async fn store_one_time_prekey(device_id: DeviceId, prekey: Vec<u8>) -> Result<()> {
    let storage = get_storage();
    let mut prekeys = storage.one_time_prekeys.write().await;
    prekeys.entry(device_id)
        .or_insert_with(Vec::new)
        .push(prekey);
    Ok(())
}

/// Consume one-time prekey (atomic)
pub async fn consume_one_time_prekey(device_id: DeviceId) -> Result<Vec<u8>> {
    let storage = get_storage();
    let mut prekeys = storage.one_time_prekeys.write().await;
    
    prekeys.get_mut(&device_id)
        .and_then(|keys| keys.pop())
        .ok_or(Error::ProtocolError("No one-time prekeys available".to_string()))
}
