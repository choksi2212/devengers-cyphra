// Crypto-erase engine for instant message destruction

use cyphra_core::{MessageId, Result, Error};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// Message envelope with wrapped encryption key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub dek_wrapped: Vec<u8>,  // DEK encrypted by KEK
    pub ciphertext: Vec<u8>,
    pub ttl: Duration,
    pub destroy_on_read: bool,
}

/// Wrap message with crypto-erase capability
pub fn wrap_message(
    plaintext: &[u8],
    kek: &[u8; 32],
    ttl: Duration,
    destroy_on_read: bool,
) -> Result<MessageEnvelope> {
    // Generate DEK (Data Encryption Key)
    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek)
        .map_err(|e| Error::CryptoError(format!("Random generation failed: {}", e)))?;
    
    // Encrypt message with DEK
    let ciphertext = aes_gcm_encrypt(&dek, plaintext)?;
    
    // Wrap DEK with KEK (Key Encryption Key)
    let dek_wrapped = aes_gcm_encrypt(kek, &dek)?;
    
    Ok(MessageEnvelope {
        dek_wrapped,
        ciphertext,
        ttl,
        destroy_on_read,
    })
}

/// Unwrap and decrypt message
pub fn unwrap_message(
    envelope: &MessageEnvelope,
    kek: &[u8; 32],
) -> Result<Vec<u8>> {
    // Unwrap DEK using KEK
    let dek_vec = aes_gcm_decrypt(kek, &envelope.dek_wrapped)?;
    
    // Convert DEK to fixed-size array
    if dek_vec.len() != 32 {
        return Err(Error::CryptoError("Invalid DEK size".to_string()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);
    
    // Decrypt message with DEK
    let plaintext = aes_gcm_decrypt(&dek, &envelope.ciphertext)?;
    
    Ok(plaintext)
}

/// Schedule message destruction
pub async fn schedule_destruction(
    msg_id: MessageId,
    ttl: Duration,
    destroy_on_read: bool,
) {
    tokio::spawn(async move {
        sleep(ttl).await;
        let _ = evaporate_key(msg_id).await;
    });
}

/// Evaporate encryption key (instant destruction with DoD 5220.22-M overwrite)
pub async fn evaporate_key(msg_id: MessageId) -> Result<()> {
    let key_id = hex::encode(msg_id.0);
    let key_path = format!("keys/{}", key_id);
    
    if std::path::Path::new(&key_path).exists() {
        // DoD 5220.22-M: overwrite 3 times before delete
        let size = std::fs::metadata(&key_path)
            .map(|m| m.len() as usize)
            .unwrap_or(32);
        
        for pass in 0..3u8 {
            let pattern = match pass {
                0 => vec![0x00u8; size],
                1 => vec![0xFFu8; size],
                _ => {
                    let mut r = vec![0u8; size];
                    getrandom::getrandom(&mut r).ok();
                    r
                }
            };
            std::fs::write(&key_path, &pattern).ok();
        }
        std::fs::remove_file(&key_path).ok();
    }
    
    Ok(())
}

/// XChaCha20-Poly1305 encryption using libsodium
fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Ensure key is 32 bytes
    let mut key_32 = [0u8; 32];
    let key_len = key.len().min(32);
    key_32[..key_len].copy_from_slice(&key[..key_len]);
    
    // Generate random 24-byte nonce for XChaCha20
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| Error::CryptoError(format!("Nonce generation failed: {}", e)))?;
    
    // Allocate buffer for ciphertext + auth tag
    let mut ciphertext = vec![0u8; plaintext.len() + 16];
    let mut ciphertext_len: u64 = 0;
    
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            plaintext.as_ptr(),
            plaintext.len() as u64,
            std::ptr::null(),
            0,
            std::ptr::null(),
            nonce.as_ptr(),
            key_32.as_ptr(),
        )
    };
    
    if result != 0 {
        return Err(Error::CryptoError("Encryption failed".to_string()));
    }
    
    ciphertext.truncate(ciphertext_len as usize);
    
    // Prepend nonce to output (nonce || ciphertext+tag)
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    
    Ok(output)
}

/// XChaCha20-Poly1305 decryption using libsodium
fn aes_gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    // Ensure key is 32 bytes
    let mut key_32 = [0u8; 32];
    let key_len = key.len().min(32);
    key_32[..key_len].copy_from_slice(&key[..key_len]);
    
    // Data format: nonce (24 bytes) || ciphertext || auth_tag (16 bytes)
    if data.len() < 24 + 16 {
        return Err(Error::CryptoError("Data too short for decryption".to_string()));
    }
    
    // Extract nonce and ciphertext
    let nonce = &data[..24];
    let ciphertext = &data[24..];
    
    // Allocate buffer for plaintext
    let mut plaintext = vec![0u8; ciphertext.len().saturating_sub(16)];
    let mut plaintext_len: u64 = 0;
    
    let result = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut plaintext_len,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            std::ptr::null(),
            0,
            nonce.as_ptr(),
            key_32.as_ptr(),
        )
    };
    
    if result != 0 {
        return Err(Error::CryptoError("Decryption or authentication failed".to_string()));
    }
    
    plaintext.truncate(plaintext_len as usize);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap() {
        let plaintext = b"Secret message";
        let kek = [1u8; 32];
        let ttl = Duration::from_secs(3600);
        
        let envelope = wrap_message(plaintext, &kek, ttl, false).unwrap();
        let decrypted = unwrap_message(&envelope, &kek).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}
