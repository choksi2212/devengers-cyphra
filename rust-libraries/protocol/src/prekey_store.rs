// Prekey storage and rotation management

use cyphra_core::{DeviceId, Result, Error};
use crate::{SignedPreKey, OneTimePreKey};
use std::collections::HashMap;

/// Prekey store
pub struct PreKeyStore {
    signed_prekeys: HashMap<DeviceId, SignedPreKey>,
    one_time_prekeys: HashMap<DeviceId, Vec<OneTimePreKey>>,
}

impl PreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
        }
    }

    /// Store signed prekey
    pub fn store_signed_prekey(&mut self, device_id: DeviceId, prekey: SignedPreKey) {
        self.signed_prekeys.insert(device_id, prekey);
    }

    /// Get signed prekey
    pub fn get_signed_prekey(&self, device_id: &DeviceId) -> Result<&SignedPreKey> {
        self.signed_prekeys
            .get(device_id)
            .ok_or(Error::DeviceNotFound)
    }

    /// Store one-time prekeys
    pub fn store_one_time_prekeys(&mut self, device_id: DeviceId, prekeys: Vec<OneTimePreKey>) {
        self.one_time_prekeys.insert(device_id, prekeys);
    }

    /// Consume one-time prekey (atomic operation)
    pub fn consume_one_time_prekey(&mut self, device_id: &DeviceId) -> Result<OneTimePreKey> {
        let prekeys = self.one_time_prekeys
            .get_mut(device_id)
            .ok_or(Error::DeviceNotFound)?;
        
        prekeys.pop().ok_or(Error::ProtocolError("No one-time prekeys available".to_string()))
    }

    /// Check if prekey rotation is needed
    pub fn needs_rotation(&self, device_id: &DeviceId) -> bool {
        if let Some(prekey) = self.signed_prekeys.get(device_id) {
            let age = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - prekey.timestamp;
            
            // Rotate weekly (7 days)
            age > 7 * 24 * 60 * 60
        } else {
            true
        }
    }

    /// Check if one-time prekeys need replenishment
    pub fn needs_replenishment(&self, device_id: &DeviceId, threshold: usize) -> bool {
        if let Some(prekeys) = self.one_time_prekeys.get(device_id) {
            prekeys.len() < threshold
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::{generate_identity_keypair, generate_signed_prekey, generate_one_time_prekeys};

    #[test]
    fn test_prekey_store() {
        let mut store = PreKeyStore::new();
        let identity = generate_identity_keypair().unwrap();
        let signed_prekey = generate_signed_prekey(&identity).unwrap();
        
        store.store_signed_prekey(identity.device_id, signed_prekey);
        
        let retrieved = store.get_signed_prekey(&identity.device_id).unwrap();
        assert!(retrieved.timestamp > 0);
    }
}
