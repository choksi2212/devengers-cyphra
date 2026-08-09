// Header encryption for metadata hiding

use cyphra_core::{Result, Error};

/// Encrypt message header
pub fn encrypt_header(header: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // TODO: Implement with ChaCha20-Poly1305
    Ok(header.to_vec())
}

/// Decrypt message header
pub fn decrypt_header(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // TODO: Implement with ChaCha20-Poly1305
    Ok(ciphertext.to_vec())
}
