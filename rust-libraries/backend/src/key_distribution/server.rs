// Key distribution server implementation

use super::{UploadBundleRequest, FetchBundleRequest, FetchBundleResponse};
use cyphra_core::{DeviceId, Result, Error};
use cyphra_protocol::PreKeyBundle;

/// Handle prekey bundle upload
pub async fn upload_prekey_bundle(req: UploadBundleRequest) -> Result<()> {
    // Verify bundle signature
    verify_bundle_signature(&req.bundle)?;
    
    // Store identity key
    super::prekey_store::store_identity_key(
        req.bundle.device_id,
        req.bundle.identity_key.clone(),
    ).await?;
    
    // Store signed prekey
    super::prekey_store::store_signed_prekey(
        req.bundle.device_id,
        req.bundle.signed_prekey.clone(),
        req.bundle.signed_prekey_signature.clone(),
    ).await?;
    
    // Store one-time prekey (if provided)
    if let Some(otk) = req.bundle.one_time_prekey {
        super::prekey_store::store_one_time_prekey(
            req.bundle.device_id,
            otk,
        ).await?;
    }
    
    Ok(())
}

/// Handle prekey bundle fetch
pub async fn fetch_prekey_bundle(req: FetchBundleRequest) -> Result<FetchBundleResponse> {
    // Check if device is revoked
    if super::revocation::is_revoked(req.device_id).await? {
        return Err(Error::KeyExpired);
    }
    
    // Fetch identity key
    let identity_key = super::prekey_store::get_identity_key(req.device_id).await?;
    
    // Fetch signed prekey
    let (signed_prekey, signed_prekey_signature) = 
        super::prekey_store::get_signed_prekey(req.device_id).await?;
    
    // Consume one-time prekey (atomic)
    let one_time_prekey = super::prekey_store::consume_one_time_prekey(req.device_id).await.ok();
    
    let bundle = PreKeyBundle {
        device_id: req.device_id,
        identity_key,
        signed_prekey,
        signed_prekey_signature,
        one_time_prekey,
    };
    
    Ok(FetchBundleResponse { bundle })
}

/// Verify bundle signature
fn verify_bundle_signature(bundle: &PreKeyBundle) -> Result<()> {
    // TODO: Verify Dilithium3 + Ed25519 signature
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_upload_bundle() {
        // TODO: Add test with valid bundle
    }
}
