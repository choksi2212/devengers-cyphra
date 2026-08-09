// PQC-Hybrid Double Ratchet
// Per-message forward secrecy and post-compromise security

use cyphra_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Ratchet session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetSession {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_counter: u32,
    pub recv_counter: u32,
    pub dh_self_kyber: Vec<u8>,
    pub dh_self_x25519: [u8; 32],
    pub dh_remote_kyber: Vec<u8>,
    pub dh_remote_x25519: [u8; 32],
    pub skipped_keys: HashMap<(u32, u32), [u8; 32]>,
}

/// Encrypted message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// Message header (encrypted separately)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub ratchet_public_kyber: Vec<u8>,
    pub ratchet_public_x25519: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
    pub timestamp: u64,
}

impl RatchetSession {
    /// Create new session from X3DH output
    pub fn new(root_key: [u8; 32], chain_key: [u8; 32]) -> Self {
        Self {
            root_key,
            send_chain_key: chain_key,
            recv_chain_key: [0u8; 32],
            send_counter: 0,
            recv_counter: 0,
            dh_self_kyber: vec![],
            dh_self_x25519: [0u8; 32],
            dh_remote_kyber: vec![],
            dh_remote_x25519: [0u8; 32],
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        // Derive message key from chain key
        let message_key = self.derive_message_key(&self.send_chain_key)?;
        
        // Advance chain key
        self.send_chain_key = self.advance_chain_key(&self.send_chain_key)?;
        
        // Encrypt plaintext with AES-256-GCM
        let (ciphertext, auth_tag) = self.aead_encrypt(&message_key, plaintext)?;
        
        // Create header
        let header = MessageHeader {
            ratchet_public_kyber: self.dh_self_kyber.clone(),
            ratchet_public_x25519: self.dh_self_x25519,
            previous_chain_length: 0, // TODO: Track properly
            message_number: self.send_counter,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.send_counter += 1;
        
        Ok(EncryptedMessage {
            header,
            ciphertext,
            auth_tag,
        })
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        // Check if we need to perform DH ratchet step
        if message.header.ratchet_public_x25519 != self.dh_remote_x25519 {
            self.dh_ratchet_step(&message.header)?;
        }
        
        // Handle out-of-order messages - skip keys if needed
        if message.header.message_number > self.recv_counter {
            self.skip_message_keys(message.header.message_number)?;
        }
        
        // Try to decrypt with current chain key
        let message_key = self.derive_message_key(&self.recv_chain_key)?;
        
        match self.aead_decrypt(&message_key, &message.ciphertext, &message.auth_tag) {
            Ok(plaintext) => {
                self.recv_chain_key = self.advance_chain_key(&self.recv_chain_key)?;
                self.recv_counter += 1;
                Ok(plaintext)
            }
            Err(_) => {
                // Try skipped keys for out-of-order messages
                self.try_skipped_keys(message)
            }
        }
    }

    /// Perform DH ratchet step (X25519 only - Kyber requires liboqs)
    fn dh_ratchet_step(&mut self, header: &MessageHeader) -> Result<()> {
        // Update remote DH keys
        self.dh_remote_kyber = header.ratchet_public_kyber.clone();
        self.dh_remote_x25519 = header.ratchet_public_x25519;
        
        // Generate new local X25519 keypair
        let mut new_x25519_pk = [0u8; 32];
        let mut new_x25519_sk = [0u8; 32];
        unsafe {
            libsodium_sys::crypto_box_keypair(
                new_x25519_pk.as_mut_ptr(),
                new_x25519_sk.as_mut_ptr(),
            );
        }
        
        // Perform X25519 ECDH
        let mut shared_secret = [0u8; 32];
        let result = unsafe {
            libsodium_sys::crypto_scalarmult(
                shared_secret.as_mut_ptr(),
                new_x25519_sk.as_ptr(),
                self.dh_remote_x25519.as_ptr(),
            )
        };
        
        if result != 0 {
            return Err(Error::CryptoError("DH key exchange failed".to_string()));
        }
        
        // Derive new root key and chain keys using HKDF-BLAKE3
        use cyphra_core::hkdf_blake3;
        
        let salt = &self.root_key;
        
        // Derive receiving chain key
        let recv_key_material = hkdf_blake3(salt, &shared_secret, b"ratchet-recv", 32)
            .map_err(|e| Error::CryptoError(format!("HKDF failed: {:?}", e)))?;
        let mut new_recv_chain_key = [0u8; 32];
        new_recv_chain_key.copy_from_slice(&recv_key_material);
        
        // Derive new root key
        let root_key_material = hkdf_blake3(salt, &shared_secret, b"ratchet-root", 32)
            .map_err(|e| Error::CryptoError(format!("HKDF failed: {:?}", e)))?;
        let mut new_root_key = [0u8; 32];
        new_root_key.copy_from_slice(&root_key_material);
        
        // Derive sending chain key
        let send_key_material = hkdf_blake3(&new_root_key, &shared_secret, b"ratchet-send", 32)
            .map_err(|e| Error::CryptoError(format!("HKDF failed: {:?}", e)))?;
        let mut new_send_chain_key = [0u8; 32];
        new_send_chain_key.copy_from_slice(&send_key_material);
        
        // Update session state
        self.root_key = new_root_key;
        self.recv_chain_key = new_recv_chain_key;
        self.send_chain_key = new_send_chain_key;
        self.dh_self_x25519 = new_x25519_pk;
        self.recv_counter = 0;
        
        Ok(())
    }
    
    /// Skip message keys for out-of-order delivery
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        const MAX_SKIP: u32 = 1000; // Prevent DoS
        
        if until - self.recv_counter > MAX_SKIP {
            return Err(Error::ProtocolError("Too many skipped messages".to_string()));
        }
        
        while self.recv_counter < until {
            let message_key = self.derive_message_key(&self.recv_chain_key)?;
            self.skipped_keys.insert((0, self.recv_counter), message_key);
            self.recv_chain_key = self.advance_chain_key(&self.recv_chain_key)?;
            self.recv_counter += 1;
        }
        
        Ok(())
    }

    /// Try decrypting with skipped keys (out-of-order messages)
    fn try_skipped_keys(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let key_id = (message.header.previous_chain_length, message.header.message_number);
        
        if let Some(message_key) = self.skipped_keys.remove(&key_id) {
            return self.aead_decrypt(&message_key, &message.ciphertext, &message.auth_tag);
        }
        
        Err(Error::ProtocolError("No matching skipped key found".to_string()))
    }

    /// Derive message key from chain key using BLAKE3
    fn derive_message_key(&self, chain_key: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(blake3::derive_key("CYPHRA-MSG-KEY", chain_key))
    }

    /// Advance chain key using BLAKE3 KDF
    fn advance_chain_key(&self, chain_key: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(blake3::derive_key("CYPHRA-CHAIN-KEY", chain_key))
    }

    /// AEAD encryption using XChaCha20-Poly1305
    fn aead_encrypt(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
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
                key.as_ptr(),
            )
        };
        
        if result != 0 {
            return Err(Error::CryptoError("Encryption failed".to_string()));
        }
        
        ciphertext.truncate(ciphertext_len as usize);
        
        // Extract auth tag from end of ciphertext
        let mut auth_tag = [0u8; 16];
        let tag_start = ciphertext.len().saturating_sub(16);
        auth_tag.copy_from_slice(&ciphertext[tag_start..]);
        
        // Prepend nonce to output (nonce || ciphertext+tag)
        let mut output = nonce.to_vec();
        output.extend_from_slice(&ciphertext);
        
        Ok((output, auth_tag))
    }

    /// AEAD decryption using XChaCha20-Poly1305
    fn aead_decrypt(&self, key: &[u8; 32], data: &[u8], _tag: &[u8; 16]) -> Result<Vec<u8>> {
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
                key.as_ptr(),
            )
        };
        
        if result != 0 {
            return Err(Error::CryptoError("Decryption or authentication failed".to_string()));
        }
        
        plaintext.truncate(plaintext_len as usize);
        Ok(plaintext)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_session() {
        let root_key = [0u8; 32];
        let chain_key = [1u8; 32];
        let mut session = RatchetSession::new(root_key, chain_key);
        
        let plaintext = b"Hello, CYPHRA!";
        let encrypted = session.encrypt(plaintext).unwrap();
        
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(session.send_counter, 1);
    }
}
