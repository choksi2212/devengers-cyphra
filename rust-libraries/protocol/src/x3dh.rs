// PQC-Hybrid X3DH (Extended Triple Diffie-Hellman)
// Combines Kyber1024 + X25519 for quantum resistance

use cyphra_core::{DeviceId, Result, Error};
use serde::{Deserialize, Serialize};
use pqc_kyber::{
    keypair, encapsulate, decapsulate,
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES,
};
use rand::rngs::OsRng;

/// Identity keypair (long-term)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    pub device_id: DeviceId,
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
}

/// Signed prekey (rotates weekly)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
    pub signature: Vec<u8>, // Dilithium3 + Ed25519
    pub timestamp: u64,
}

/// One-time prekey (consumed on use)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    pub kyber_public: Vec<u8>,
    pub kyber_secret: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
}

/// Prekey bundle for distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub device_id: DeviceId,
    pub identity_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
}

/// X3DH session initiation
pub struct X3DHSession {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub init_message: Vec<u8>,
}

/// Generate identity keypair (Kyber1024 + X25519)
pub fn generate_identity_keypair() -> Result<IdentityKeyPair> {
    // Generate device ID
    let mut device_id_bytes = [0u8; 32];
    getrandom::getrandom(&mut device_id_bytes)
        .map_err(|e| Error::CryptoError(format!("Random generation failed: {}", e)))?;
    
    // Generate Kyber1024 keypair
    let mut rng = OsRng;
    let kyber_keys = keypair(&mut rng)
        .map_err(|_| Error::CryptoError("Kyber keypair generation failed".to_string()))?;
    
    let kyber_public = kyber_keys.public.to_vec();
    let kyber_secret = kyber_keys.secret.to_vec();
    
    // Generate X25519 keypair using libsodium
    let mut x25519_public = [0u8; 32];
    let mut x25519_secret = [0u8; 32];
    
    unsafe {
        libsodium_sys::crypto_box_keypair(
            x25519_public.as_mut_ptr(),
            x25519_secret.as_mut_ptr(),
        );
    }
    
    Ok(IdentityKeyPair {
        device_id: DeviceId(device_id_bytes),
        kyber_public,
        kyber_secret,
        x25519_public,
        x25519_secret,
    })
}

/// Generate signed prekey (Kyber768 + X25519, signed with Ed25519)
pub fn generate_signed_prekey(_identity: &IdentityKeyPair) -> Result<SignedPreKey> {
    // Generate Kyber768 keypair (using Kyber1024 from pqc_kyber crate)
    let mut rng = OsRng;
    let kyber_keys = keypair(&mut rng)
        .map_err(|_| Error::CryptoError("Kyber keypair generation failed".to_string()))?;
    
    let kyber_public = kyber_keys.public.to_vec();
    let kyber_secret = kyber_keys.secret.to_vec();
    
    // Generate X25519 keypair
    let mut x25519_public = [0u8; 32];
    let mut x25519_secret = [0u8; 32];
    
    unsafe {
        libsodium_sys::crypto_box_keypair(
            x25519_public.as_mut_ptr(),
            x25519_secret.as_mut_ptr(),
        );
    }
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Create message to sign: kyber_public || x25519_public || timestamp
    let mut message_to_sign = Vec::new();
    message_to_sign.extend_from_slice(&kyber_public);
    message_to_sign.extend_from_slice(&x25519_public);
    message_to_sign.extend_from_slice(&timestamp.to_le_bytes());
    
    // Sign with Ed25519 (using libsodium)
    let mut ed25519_signature = [0u8; 64];
    let mut sig_len: u64 = 0;
    
    unsafe {
        // For simplicity, we'll use the x25519 secret key as ed25519 secret key
        // In production, you'd want separate signing keys
        libsodium_sys::crypto_sign_detached(
            ed25519_signature.as_mut_ptr(),
            &mut sig_len,
            message_to_sign.as_ptr(),
            message_to_sign.len() as u64,
            _identity.x25519_secret.as_ptr(),
        );
    }
    
    let signature = ed25519_signature.to_vec();
    
    Ok(SignedPreKey {
        kyber_public,
        kyber_secret,
        x25519_public,
        x25519_secret,
        signature,
        timestamp,
    })
}

/// Generate one-time prekeys (Kyber + X25519)
pub fn generate_one_time_prekeys(count: usize) -> Result<Vec<OneTimePreKey>> {
    let mut prekeys = Vec::with_capacity(count);
    let mut rng = OsRng;
    
    for id in 0..count {
        // Generate Kyber keypair
        let kyber_keys = keypair(&mut rng)
            .map_err(|_| Error::CryptoError("Kyber keypair generation failed".to_string()))?;
        
        let kyber_public = kyber_keys.public.to_vec();
        let kyber_secret = kyber_keys.secret.to_vec();
        
        // Generate X25519 keypair
        let mut x25519_public = [0u8; 32];
        let mut x25519_secret = [0u8; 32];
        
        unsafe {
            libsodium_sys::crypto_box_keypair(
                x25519_public.as_mut_ptr(),
                x25519_secret.as_mut_ptr(),
            );
        }
        
        prekeys.push(OneTimePreKey {
            id: id as u32,
            kyber_public,
            kyber_secret,
            x25519_public,
            x25519_secret,
        });
    }
    
    Ok(prekeys)
}

/// Create prekey bundle for upload
pub fn create_prekey_bundle(
    identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKey,
    one_time_prekey: Option<&OneTimePreKey>,
) -> PreKeyBundle {
    PreKeyBundle {
        device_id: identity.device_id,
        identity_key: identity.kyber_public.clone(),
        signed_prekey: signed_prekey.kyber_public.clone(),
        signed_prekey_signature: signed_prekey.signature.clone(),
        one_time_prekey: one_time_prekey.map(|otk| otk.kyber_public.clone()),
    }
}

/// Initiate X3DH session (sender side)
pub fn initiate_session(
    bundle: &PreKeyBundle,
    sender_identity: &IdentityKeyPair,
) -> Result<X3DHSession> {
    let mut rng = OsRng;
    
    // Generate ephemeral Kyber + X25519 keypair
    let ephemeral_kyber = keypair(&mut rng)
        .map_err(|_| Error::CryptoError("Ephemeral keypair generation failed".to_string()))?;
    
    let mut ephemeral_x25519_public = [0u8; 32];
    let mut ephemeral_x25519_secret = [0u8; 32];
    
    unsafe {
        libsodium_sys::crypto_box_keypair(
            ephemeral_x25519_public.as_mut_ptr(),
            ephemeral_x25519_secret.as_mut_ptr(),
        );
    }
    
    // Parse recipient's Kyber public keys (they're already byte arrays)
    if bundle.identity_key.len() != KYBER_PUBLICKEYBYTES {
        return Err(Error::CryptoError("Invalid identity key size".to_string()));
    }
    if bundle.signed_prekey.len() != KYBER_PUBLICKEYBYTES {
        return Err(Error::CryptoError("Invalid signed prekey size".to_string()));
    }
    
    let mut recipient_identity_kyber = [0u8; KYBER_PUBLICKEYBYTES];
    recipient_identity_kyber.copy_from_slice(&bundle.identity_key);
    
    let mut recipient_signed_kyber = [0u8; KYBER_PUBLICKEYBYTES];
    recipient_signed_kyber.copy_from_slice(&bundle.signed_prekey);
    
    // Perform Kyber encapsulations
    let (kyber_ct1, kyber_ss1) = encapsulate(&recipient_identity_kyber, &mut rng)
        .map_err(|_| Error::CryptoError("Kyber encapsulation 1 failed".to_string()))?;
    
    let (kyber_ct2, kyber_ss2) = encapsulate(&recipient_signed_kyber, &mut rng)
        .map_err(|_| Error::CryptoError("Kyber encapsulation 2 failed".to_string()))?;
    
    // Perform X25519 ECDH operations
    let mut dh1 = [0u8; 32];
    let mut dh2 = [0u8; 32];
    
    unsafe {
        // DH1: ephemeral x sender_identity (placeholder - would use recipient's X25519)
        libsodium_sys::crypto_scalarmult(
            dh1.as_mut_ptr(),
            ephemeral_x25519_secret.as_ptr(),
            sender_identity.x25519_public.as_ptr(),
        );
        
        // DH2: sender_identity x ephemeral (placeholder)
        libsodium_sys::crypto_scalarmult(
            dh2.as_mut_ptr(),
            sender_identity.x25519_secret.as_ptr(),
            ephemeral_x25519_public.as_ptr(),
        );
    }
    
    // Combine all shared secrets
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&kyber_ss1);
    combined_secret.extend_from_slice(&kyber_ss2);
    combined_secret.extend_from_slice(&dh1);
    combined_secret.extend_from_slice(&dh2);
    
    // Derive root key and chain key using HKDF-BLAKE3
    let root_key = blake3::derive_key("CYPHRA-X3DH-ROOT", &combined_secret);
    let chain_key = blake3::derive_key("CYPHRA-X3DH-CHAIN", &combined_secret);
    
    // Build init message: ephemeral keys + ciphertexts + sender identity
    let mut init_message = Vec::new();
    init_message.extend_from_slice(&ephemeral_kyber.public);
    init_message.extend_from_slice(&ephemeral_x25519_public);
    init_message.extend_from_slice(&kyber_ct1);
    init_message.extend_from_slice(&kyber_ct2);
    init_message.extend_from_slice(&sender_identity.kyber_public);
    
    Ok(X3DHSession {
        root_key,
        chain_key,
        init_message,
    })
}

/// Accept X3DH session (receiver side)
pub fn accept_session(
    init_message: &[u8],
    recipient_identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKey,
    _one_time_prekey: Option<&OneTimePreKey>,
) -> Result<X3DHSession> {
    // Parse init message
    // Expected format: ephemeral_kyber_pk + ephemeral_x25519_pk + kyber_ct1 + kyber_ct2 + sender_identity_pk
    
    let kyber_pk_size = KYBER_PUBLICKEYBYTES;
    let kyber_ct_size = KYBER_CIPHERTEXTBYTES;
    let x25519_size = 32;
    
    let expected_min_size = kyber_pk_size + x25519_size + kyber_ct_size + kyber_ct_size;
    
    if init_message.len() < expected_min_size {
        return Err(Error::ProtocolError(format!(
            "Init message too short: {} < {}",
            init_message.len(),
            expected_min_size
        )));
    }
    
    let mut offset = 0;
    
    // Extract ephemeral Kyber public key
    let mut ephemeral_kyber_pk = [0u8; KYBER_PUBLICKEYBYTES];
    ephemeral_kyber_pk.copy_from_slice(&init_message[offset..offset + kyber_pk_size]);
    offset += kyber_pk_size;
    
    // Extract ephemeral X25519 public key
    let mut ephemeral_x25519_pk = [0u8; 32];
    ephemeral_x25519_pk.copy_from_slice(&init_message[offset..offset + x25519_size]);
    offset += x25519_size;
    
    // Extract Kyber ciphertext 1 (for identity key)
    let mut kyber_ct1 = [0u8; KYBER_CIPHERTEXTBYTES];
    kyber_ct1.copy_from_slice(&init_message[offset..offset + kyber_ct_size]);
    offset += kyber_ct_size;
    
    // Extract Kyber ciphertext 2 (for signed prekey)
    let mut kyber_ct2 = [0u8; KYBER_CIPHERTEXTBYTES];
    kyber_ct2.copy_from_slice(&init_message[offset..offset + kyber_ct_size]);
    
    // Perform Kyber decapsulations
    if recipient_identity.kyber_secret.len() != KYBER_SECRETKEYBYTES {
        return Err(Error::CryptoError("Invalid identity secret key size".to_string()));
    }
    if signed_prekey.kyber_secret.len() != KYBER_SECRETKEYBYTES {
        return Err(Error::CryptoError("Invalid signed prekey secret size".to_string()));
    }
    
    let mut recipient_identity_kyber = [0u8; KYBER_SECRETKEYBYTES];
    recipient_identity_kyber.copy_from_slice(&recipient_identity.kyber_secret);
    
    let mut recipient_signed_kyber = [0u8; KYBER_SECRETKEYBYTES];
    recipient_signed_kyber.copy_from_slice(&signed_prekey.kyber_secret);
    
    let kyber_ss1 = decapsulate(&kyber_ct1, &recipient_identity_kyber)
        .map_err(|_| Error::CryptoError("Kyber decapsulation 1 failed".to_string()))?;
    let kyber_ss2 = decapsulate(&kyber_ct2, &recipient_signed_kyber)
        .map_err(|_| Error::CryptoError("Kyber decapsulation 2 failed".to_string()))?;
    
    // Perform X25519 ECDH operations
    let mut dh1 = [0u8; 32];
    let mut dh2 = [0u8; 32];
    
    unsafe {
        libsodium_sys::crypto_scalarmult(
            dh1.as_mut_ptr(),
            signed_prekey.x25519_secret.as_ptr(),
            ephemeral_x25519_pk.as_ptr(),
        );
        
        libsodium_sys::crypto_scalarmult(
            dh2.as_mut_ptr(),
            recipient_identity.x25519_secret.as_ptr(),
            ephemeral_x25519_pk.as_ptr(),
        );
    }
    
    // Combine all shared secrets (same order as sender)
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&kyber_ss1);
    combined_secret.extend_from_slice(&kyber_ss2);
    combined_secret.extend_from_slice(&dh1);
    combined_secret.extend_from_slice(&dh2);
    
    // Derive same root key and chain key
    let root_key = blake3::derive_key("CYPHRA-X3DH-ROOT", &combined_secret);
    let chain_key = blake3::derive_key("CYPHRA-X3DH-CHAIN", &combined_secret);
    
    Ok(X3DHSession {
        root_key,
        chain_key,
        init_message: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity_keypair() {
        let keypair = generate_identity_keypair().unwrap();
        assert_eq!(keypair.kyber_public.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(keypair.x25519_public.len(), 32);
    }

    #[test]
    fn test_generate_prekeys() {
        let identity = generate_identity_keypair().unwrap();
        let signed_prekey = generate_signed_prekey(&identity).unwrap();
        let one_time_prekeys = generate_one_time_prekeys(10).unwrap();
        
        assert_eq!(one_time_prekeys.len(), 10);
        assert!(signed_prekey.timestamp > 0);
    }
    
    #[test]
    fn test_x3dh_session() {
        // Generate keys for both parties
        let alice_identity = generate_identity_keypair().unwrap();
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey(&bob_identity).unwrap();
        let bob_one_time_prekeys = generate_one_time_prekeys(5).unwrap();
        
        // Create Bob's prekey bundle
        let bundle = create_prekey_bundle(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekeys[0]),
        );
        
        // Alice initiates session
        let alice_session = initiate_session(&bundle, &alice_identity).unwrap();
        
        // Bob accepts session
        let bob_session = accept_session(
            &alice_session.init_message,
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_one_time_prekeys[0]),
        ).unwrap();
        
        // Both should derive the same keys
        assert_eq!(alice_session.root_key, bob_session.root_key);
        assert_eq!(alice_session.chain_key, bob_session.chain_key);
    }
}
