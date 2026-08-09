//! Cryptographic utility functions

use crate::{Result, Error};
use blake3;

/// HKDF-BLAKE3 key derivation
/// 
/// Implements HKDF (HMAC-based Key Derivation Function) using BLAKE3
/// as the underlying hash function.
pub fn hkdf_blake3(
    salt: &[u8],
    ikm: &[u8],  // Input Key Material
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    let prk = blake3::keyed_hash(
        &salt_to_key(salt),
        ikm,
    );
    
    // HKDF-Expand: OKM = HMAC-Hash(PRK, info || 0x01)
    let mut output = Vec::with_capacity(output_len);
    let mut counter = 1u8;
    let mut previous = Vec::new();
    
    while output.len() < output_len {
        let mut input = previous.clone();
        input.extend_from_slice(info);
        input.push(counter);
        
        let hash = blake3::keyed_hash(prk.as_bytes(), &input);
        previous = hash.as_bytes().to_vec();
        
        let remaining = output_len - output.len();
        let to_copy = remaining.min(32);
        output.extend_from_slice(&previous[..to_copy]);
        
        counter += 1;
        if counter == 0 {
            return Err(Error::CryptoError("HKDF output too long".to_string()));
        }
    }
    
    Ok(output)
}

/// Convert salt to BLAKE3 key (32 bytes)
fn salt_to_key(salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if salt.is_empty() {
        // Use zero key if no salt provided
        return key;
    }
    
    if salt.len() >= 32 {
        key.copy_from_slice(&salt[..32]);
    } else {
        key[..salt.len()].copy_from_slice(salt);
    }
    key
}

/// Derive two keys from shared secret using HKDF-BLAKE3
pub fn derive_key_pair(
    shared_secret: &[u8],
    salt: &[u8],
    info1: &str,
    info2: &str,
) -> Result<([u8; 32], [u8; 32])> {
    let key1_bytes = hkdf_blake3(salt, shared_secret, info1.as_bytes(), 32)?;
    let key2_bytes = hkdf_blake3(salt, shared_secret, info2.as_bytes(), 32)?;
    
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key1.copy_from_slice(&key1_bytes);
    key2.copy_from_slice(&key2_bytes);
    
    Ok((key1, key2))
}

/// Initialize libsodium (must be called before using any libsodium functions)
pub fn init_libsodium() -> Result<()> {
    let result = unsafe { libsodium_sys::sodium_init() };
    if result < 0 {
        return Err(Error::CryptoError("Failed to initialize libsodium".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_blake3() {
        let salt = b"test-salt";
        let ikm = b"input-key-material";
        let info = b"test-info";
        
        let output = hkdf_blake3(salt, ikm, info, 64).unwrap();
        assert_eq!(output.len(), 64);
        
        // Deterministic output
        let output2 = hkdf_blake3(salt, ikm, info, 64).unwrap();
        assert_eq!(output, output2);
    }
    
    #[test]
    fn test_derive_key_pair() {
        let shared_secret = b"shared-secret-data";
        let salt = b"salt";
        
        let (key1, key2) = derive_key_pair(shared_secret, salt, "key1", "key2").unwrap();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Should be deterministic
        let (key1_again, key2_again) = derive_key_pair(shared_secret, salt, "key1", "key2").unwrap();
        assert_eq!(key1, key1_again);
        assert_eq!(key2, key2_again);
    }
}
