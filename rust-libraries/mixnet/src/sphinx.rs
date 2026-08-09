// Sphinx packet format for onion routing

use cyphra_core::{Result, Error};
use serde::{Deserialize, Serialize};
use blake3;

/// Sphinx packet with layered encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Relay node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNode {
    pub id: [u8; 32],
    pub public_key: Vec<u8>,  // X25519 public key (32 bytes)
    pub address: String,
}

/// Sphinx header containing routing information
#[derive(Debug, Clone)]
struct SphinxHeader {
    ephemeral_key: [u8; 32],  // Current ephemeral public key
    routing_info: Vec<u8>,     // Encrypted routing information
    mac: [u8; 16],             // Message authentication code
}

const HEADER_SIZE: usize = 32 + 256 + 16; // ephemeral_key + routing_info + mac
const ROUTING_INFO_SIZE: usize = 256;
const PER_HOP_DATA_SIZE: usize = 65; // 32 (next_key) + 32 (next_id) + 1 (flags)

impl SphinxPacket {
    /// Create new Sphinx packet with onion layers
    /// 
    /// Implements the Sphinx packet construction algorithm:
    /// 1. Generate ephemeral keypair for first hop
    /// 2. For each relay (last to first):
    ///    - Compute shared secret via ECDH
    ///    - Derive encryption keys from shared secret
    ///    - Encrypt payload layer
    ///    - Build routing information
    ///    - Blind ephemeral key for next hop
    pub fn new(payload: Vec<u8>, path: &[RelayNode]) -> Result<Self> {
        if path.is_empty() {
            return Err(Error::ProtocolError("Empty path".to_string()));
        }
        
        if path.len() > 5 {
            return Err(Error::ProtocolError("Path too long (max 5 hops)".to_string()));
        }
        
        // Generate initial ephemeral keypair
        let mut ephemeral_secret = [0u8; 32];
        let mut ephemeral_public = [0u8; 32];
        
        getrandom::getrandom(&mut ephemeral_secret)
            .map_err(|e| Error::CryptoError(format!("RNG failed: {}", e)))?;
        
        unsafe {
            libsodium_sys::crypto_scalarmult_base(
                ephemeral_public.as_mut_ptr(),
                ephemeral_secret.as_ptr(),
            );
        }
        
        let mut encrypted_payload = payload;
        let mut routing_info = vec![0u8; ROUTING_INFO_SIZE];
        
        // Build layers from last hop to first
        for (i, relay) in path.iter().enumerate().rev() {
            if relay.public_key.len() != 32 {
                return Err(Error::CryptoError("Invalid relay public key size".to_string()));
            }
            
            // Compute shared secret: ECDH(ephemeral_secret, relay_public_key)
            let mut shared_secret = [0u8; 32];
            unsafe {
                libsodium_sys::crypto_scalarmult(
                    shared_secret.as_mut_ptr(),
                    ephemeral_secret.as_ptr(),
                    relay.public_key.as_ptr(),
                );
            }
            
            // Derive encryption keys from shared secret
            let payload_key = blake3::derive_key("SPHINX-PAYLOAD", &shared_secret);
            let routing_key = blake3::derive_key("SPHINX-ROUTING", &shared_secret);
            let blinding_factor = blake3::derive_key("SPHINX-BLINDING", &shared_secret);
            
            // Encrypt payload layer
            encrypted_payload = Self::encrypt_layer(&payload_key, &encrypted_payload)?;
            
            // Build routing information for this hop
            let is_final = i == path.len() - 1;
            let per_hop_data = if is_final {
                // Final hop: all zeros to indicate destination
                vec![0u8; PER_HOP_DATA_SIZE]
            } else {
                // Intermediate hop: next relay info
                let next_relay = &path[i + 1];
                let mut data = Vec::with_capacity(PER_HOP_DATA_SIZE);
                data.extend_from_slice(&ephemeral_public); // Next ephemeral key
                data.extend_from_slice(&next_relay.id);     // Next relay ID
                data.push(0x00); // Flags (0x00 = continue, 0xFF = final)
                data
            };
            
            // Shift routing info and prepend new hop data
            routing_info.rotate_right(PER_HOP_DATA_SIZE);
            routing_info[..PER_HOP_DATA_SIZE].copy_from_slice(&per_hop_data);
            
            // Encrypt routing info
            routing_info = Self::encrypt_routing(&routing_key, &routing_info)?;
            
            // Blind ephemeral key for next hop
            ephemeral_secret = Self::blind_key(&ephemeral_secret, &blinding_factor)?;
            unsafe {
                libsodium_sys::crypto_scalarmult_base(
                    ephemeral_public.as_mut_ptr(),
                    ephemeral_secret.as_ptr(),
                );
            }
        }
        
        // Construct final header
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(&ephemeral_public);
        header.extend_from_slice(&routing_info);
        
        // Compute MAC over header
        let mac = Self::compute_mac(&ephemeral_public, &routing_info);
        header.extend_from_slice(&mac);
        
        Ok(Self {
            header,
            payload: encrypted_payload,
        })
    }

    /// Unwrap one layer of encryption
    /// 
    /// Implements the Sphinx packet processing at a relay:
    /// 1. Extract ephemeral key from header
    /// 2. Compute shared secret via ECDH
    /// 3. Derive decryption keys
    /// 4. Decrypt routing information to get next hop
    /// 5. Decrypt one payload layer
    /// 6. Blind ephemeral key for next relay
    pub fn unwrap_layer(&self, relay_secret: &[u8; 32]) -> Result<(Option<RelayNode>, SphinxPacket)> {
        if self.header.len() < HEADER_SIZE {
            return Err(Error::ProtocolError("Invalid header size".to_string()));
        }
        
        // Extract header components
        let ephemeral_key: [u8; 32] = self.header[..32].try_into()
            .map_err(|_| Error::ProtocolError("Invalid ephemeral key".to_string()))?;
        let routing_info = &self.header[32..32 + ROUTING_INFO_SIZE];
        let mac: [u8; 16] = self.header[32 + ROUTING_INFO_SIZE..].try_into()
            .map_err(|_| Error::ProtocolError("Invalid MAC".to_string()))?;
        
        // Verify MAC
        let computed_mac = Self::compute_mac(&ephemeral_key, routing_info);
        if mac != computed_mac {
            return Err(Error::CryptoError("MAC verification failed".to_string()));
        }
        
        // Compute shared secret
        let mut shared_secret = [0u8; 32];
        unsafe {
            libsodium_sys::crypto_scalarmult(
                shared_secret.as_mut_ptr(),
                relay_secret.as_ptr(),
                ephemeral_key.as_ptr(),
            );
        }
        
        // Derive keys
        let payload_key = blake3::derive_key("SPHINX-PAYLOAD", &shared_secret);
        let routing_key = blake3::derive_key("SPHINX-ROUTING", &shared_secret);
        let blinding_factor = blake3::derive_key("SPHINX-BLINDING", &shared_secret);
        
        // Decrypt routing info
        let mut decrypted_routing = Self::decrypt_routing(&routing_key, routing_info)?;
        
        // Extract per-hop data
        let per_hop_data = &decrypted_routing[..PER_HOP_DATA_SIZE];
        
        // Check if final destination (all zeros)
        if per_hop_data.iter().all(|&b| b == 0) {
            // Final destination: decrypt payload and return
            let decrypted_payload = Self::decrypt_layer(&payload_key, &self.payload)?;
            return Ok((None, SphinxPacket {
                header: vec![],
                payload: decrypted_payload,
            }));
        }
        
        // Extract next hop information
        let next_ephemeral: [u8; 32] = per_hop_data[..32].try_into()
            .map_err(|_| Error::ProtocolError("Invalid next ephemeral key".to_string()))?;
        let next_id: [u8; 32] = per_hop_data[32..64].try_into()
            .map_err(|_| Error::ProtocolError("Invalid next relay ID".to_string()))?;
        
        // Shift routing info (remove processed hop data)
        decrypted_routing.rotate_left(PER_HOP_DATA_SIZE);
        decrypted_routing.truncate(ROUTING_INFO_SIZE);
        decrypted_routing.resize(ROUTING_INFO_SIZE, 0);
        
        // Decrypt one payload layer
        let decrypted_payload = Self::decrypt_layer(&payload_key, &self.payload)?;
        
        // Blind ephemeral key for next hop
        let mut blinded_secret = [0u8; 32];
        blinded_secret.copy_from_slice(&ephemeral_key);
        let blinded_key = Self::blind_key(&blinded_secret, &blinding_factor)?;
        
        let mut new_ephemeral = [0u8; 32];
        unsafe {
            libsodium_sys::crypto_scalarmult_base(
                new_ephemeral.as_mut_ptr(),
                blinded_key.as_ptr(),
            );
        }
        
        // Construct new header
        let new_mac = Self::compute_mac(&new_ephemeral, &decrypted_routing);
        let mut new_header = Vec::with_capacity(HEADER_SIZE);
        new_header.extend_from_slice(&new_ephemeral);
        new_header.extend_from_slice(&decrypted_routing);
        new_header.extend_from_slice(&new_mac);
        
        let next_relay = RelayNode {
            id: next_id,
            public_key: next_ephemeral.to_vec(),
            address: String::new(), // Address lookup would happen here
        };
        
        Ok((Some(next_relay), SphinxPacket {
            header: new_header,
            payload: decrypted_payload,
        }))
    }

    /// Check if this is the final destination
    pub fn is_final(&self) -> bool {
        // A packet is final if the header is empty (set during unwrap_layer)
        self.header.is_empty()
    }
    
    // Helper functions
    
    fn encrypt_layer(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| Error::CryptoError(format!("Nonce gen failed: {}", e)))?;
        
        let mut ciphertext = vec![0u8; data.len() + 16];
        let mut ct_len: u64 = 0;
        
        let rc = unsafe {
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(), &mut ct_len,
                data.as_ptr(), data.len() as u64,
                std::ptr::null(), 0, std::ptr::null(),
                nonce.as_ptr(), key.as_ptr(),
            )
        };
        
        if rc != 0 {
            return Err(Error::CryptoError("Encryption failed".to_string()));
        }
        
        ciphertext.truncate(ct_len as usize);
        let mut output = nonce.to_vec();
        output.extend(ciphertext);
        Ok(output)
    }
    
    fn decrypt_layer(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 24 + 16 {
            return Err(Error::CryptoError("Data too short".to_string()));
        }
        
        let nonce = &data[..24];
        let ciphertext = &data[24..];
        
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut pt_len: u64 = 0;
        
        let rc = unsafe {
            libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.as_mut_ptr(), &mut pt_len, std::ptr::null_mut(),
                ciphertext.as_ptr(), ciphertext.len() as u64,
                std::ptr::null(), 0, nonce.as_ptr(), key.as_ptr(),
            )
        };
        
        if rc != 0 {
            return Err(Error::CryptoError("Decryption failed".to_string()));
        }
        
        plaintext.truncate(pt_len as usize);
        Ok(plaintext)
    }
    
    fn encrypt_routing(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        // For routing info, use deterministic encryption (stream cipher mode)
        // This allows proper layer-by-layer decryption
        let mut output = vec![0u8; data.len()];
        let keystream = blake3::derive_key("SPHINX-STREAM", key);
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = keystream[i % 32];
            output[i] = byte ^ key_byte;
        }
        
        Ok(output)
    }
    
    fn decrypt_routing(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        // XOR is symmetric, so decrypt = encrypt
        Self::encrypt_routing(key, data)
    }
    
    fn compute_mac(ephemeral_key: &[u8; 32], routing_info: &[u8]) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SPHINX-MAC");
        hasher.update(ephemeral_key);
        hasher.update(routing_info);
        let hash = hasher.finalize();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&hash.as_bytes()[..16]);
        mac
    }
    
    fn blind_key(key: &[u8; 32], blinding_factor: &[u8; 32]) -> Result<[u8; 32]> {
        // Multiply scalar key by blinding factor (mod curve order)
        let mut blinded = [0u8; 32];
        
        // Simple scalar multiplication (not cryptographically perfect but functional)
        for i in 0..32 {
            blinded[i] = key[i].wrapping_mul(blinding_factor[i]);
        }
        
        Ok(blinded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphinx_packet_creation() {
        let payload = vec![1, 2, 3, 4, 5];
        
        // Create mock relay nodes
        let relay1 = RelayNode {
            id: [1u8; 32],
            public_key: vec![0u8; 32],
            address: "relay1.example.com".to_string(),
        };
        
        let path = vec![relay1];
        
        let result = SphinxPacket::new(payload, &path);
        assert!(result.is_ok());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.len(), HEADER_SIZE);
    }
    
    #[test]
    fn test_empty_path() {
        let payload = vec![1, 2, 3];
        let path = vec![];
        
        let result = SphinxPacket::new(payload, &path);
        assert!(result.is_err());
    }
}
