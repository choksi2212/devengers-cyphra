// Key revocation management

use cyphra_core::{DeviceId, Result};
use std::collections::HashSet;
use tokio::sync::RwLock;
use std::sync::Arc;

struct RevocationList {
    revoked: Arc<RwLock<HashSet<DeviceId>>>,
}

impl RevocationList {
    fn new() -> Self {
        Self {
            revoked: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

static mut GLOBAL_REVOCATION: Option<RevocationList> = None;

fn get_revocation_list() -> &'static RevocationList {
    unsafe {
        GLOBAL_REVOCATION.get_or_insert_with(|| RevocationList::new())
    }
}

/// Add device to revocation list
pub async fn add_to_revocation_list(device_id: DeviceId) -> Result<()> {
    let list = get_revocation_list();
    let mut revoked = list.revoked.write().await;
    revoked.insert(device_id);
    Ok(())
}

/// Check if device is revoked
pub async fn is_revoked(device_id: DeviceId) -> Result<bool> {
    let list = get_revocation_list();
    let revoked = list.revoked.read().await;
    Ok(revoked.contains(&device_id))
}

/// Remove from revocation list
pub async fn remove_from_revocation_list(device_id: DeviceId) -> Result<()> {
    let list = get_revocation_list();
    let mut revoked = list.revoked.write().await;
    revoked.remove(&device_id);
    Ok(())
}
