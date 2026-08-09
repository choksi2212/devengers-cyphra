//! CYPHRA WASM Cryptographic Bridge
//!
//! Exposes AES-256-GCM encryption, X25519 ECDH key exchange,
//! Ed25519 signing/verification, HKDF-SHA256 key derivation,
//! and BLAKE3-style hashing — all as WebAssembly exports.
//!
//! Uses ONLY pure-Rust crates (no C FFI) so it compiles cleanly
//! to wasm32-unknown-unknown via wasm-pack.

use wasm_bindgen::prelude::*;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use ed25519_dalek::{
    Signer, Verifier,
    SigningKey, VerifyingKey, Signature,
};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use rand_core::OsRng;
use getrandom::getrandom;

use hex;

// ──────────────────────────────────────────────────────────────────────────────
// Utility: secure random bytes

#[wasm_bindgen]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom(&mut buf).expect("getrandom failed");
    buf
}

// ──────────────────────────────────────────────────────────────────────────────
// AES-256-GCM Encryption

/// Encrypt plaintext with AES-256-GCM.
/// 
/// # Arguments
/// * `key_bytes` — 32-byte AES key
/// * `plaintext` — data to encrypt
/// 
/// Returns JSON: `{ ciphertext: hex, nonce: hex }`
#[wasm_bindgen]
pub fn aes_gcm_encrypt(key_bytes: &[u8], plaintext: &[u8]) -> Result<String, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    Ok(format!(
        r#"{{"ciphertext":"{}","nonce":"{}"}}"#,
        hex::encode(&ciphertext),
        hex::encode(&nonce_bytes)
    ))
}

/// Decrypt ciphertext with AES-256-GCM.
/// 
/// # Arguments
/// * `key_bytes` — 32-byte AES key
/// * `ciphertext_hex` — hex-encoded ciphertext+tag
/// * `nonce_hex` — hex-encoded 12-byte nonce
/// 
/// Returns plaintext bytes on success.
#[wasm_bindgen]
pub fn aes_gcm_decrypt(key_bytes: &[u8], ciphertext_hex: &str, nonce_hex: &str) -> Result<Vec<u8>, JsValue> {
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }

    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid ciphertext hex: {}", e)))?;
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid nonce hex: {}", e)))?;

    if nonce_bytes.len() != 12 {
        return Err(JsValue::from_str("Nonce must be 12 bytes"));
    }

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsValue::from_str(&format!("Decryption failed (wrong key/data): {}", e)))
}

// ──────────────────────────────────────────────────────────────────────────────
// X25519 ECDH Key Exchange

/// Generate a fresh X25519 key pair.
/// Returns JSON: `{ public_key: hex, private_key: hex }`
#[wasm_bindgen]
pub fn x25519_generate_keypair() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519Public::from(&secret);
    format!(
        r#"{{"public_key":"{}","private_key":"{}"}}"#,
        hex::encode(public.as_bytes()),
        hex::encode(secret.as_bytes())
    )
}

/// Perform X25519 Diffie-Hellman to derive a shared secret.
/// 
/// # Arguments
/// * `private_key_hex` — 32-byte private key in hex
/// * `peer_public_key_hex` — 32-byte peer public key in hex
/// 
/// Returns shared secret as hex string.
#[wasm_bindgen]
pub fn x25519_diffie_hellman(private_key_hex: &str, peer_public_key_hex: &str) -> Result<String, JsValue> {
    let priv_bytes: [u8; 32] = hex::decode(private_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid private key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Private key must be 32 bytes"))?;

    let pub_bytes: [u8; 32] = hex::decode(peer_public_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Public key must be 32 bytes"))?;

    let secret = StaticSecret::from(priv_bytes);
    let peer_pub = X25519Public::from(pub_bytes);
    let shared = secret.diffie_hellman(&peer_pub);

    Ok(hex::encode(shared.as_bytes()))
}

// ──────────────────────────────────────────────────────────────────────────────
// HKDF-SHA256 Key Derivation

/// Derive key material using HKDF-SHA256.
/// 
/// # Arguments
/// * `ikm` — Input Key Material (e.g. DH shared secret)
/// * `salt` — Optional salt (empty = zero bytes)
/// * `info` — Context/application info
/// * `output_len` — Desired output length in bytes (max 255 * 32 = 8160)
/// 
/// Returns derived key as hex string.
#[wasm_bindgen]
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<String, JsValue> {
    let hk = if salt.is_empty() {
        Hkdf::<Sha256>::new(None, ikm)
    } else {
        Hkdf::<Sha256>::new(Some(salt), ikm)
    };

    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| JsValue::from_str("HKDF expand failed: output too long"))?;

    Ok(hex::encode(&okm))
}

// ──────────────────────────────────────────────────────────────────────────────
// Ed25519 Digital Signatures

/// Generate a fresh Ed25519 signing key pair.
/// Returns JSON: `{ verifying_key: hex, signing_key: hex }`
#[wasm_bindgen]
pub fn ed25519_generate_keypair() -> String {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    format!(
        r#"{{"verifying_key":"{}","signing_key":"{}"}}"#,
        hex::encode(verifying_key.as_bytes()),
        hex::encode(signing_key.as_bytes())
    )
}

/// Sign a message using Ed25519.
/// 
/// # Arguments
/// * `signing_key_hex` — 32-byte Ed25519 signing key in hex
/// * `message` — data to sign
/// 
/// Returns signature as hex string (64 bytes).
#[wasm_bindgen]
pub fn ed25519_sign(signing_key_hex: &str, message: &[u8]) -> Result<String, JsValue> {
    let key_bytes: [u8; 32] = hex::decode(signing_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid signing key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Signing key must be 32 bytes"))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(message);
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify an Ed25519 signature.
/// 
/// # Arguments
/// * `verifying_key_hex` — 32-byte Ed25519 verifying key in hex
/// * `message` — original data that was signed
/// * `signature_hex` — 64-byte signature in hex
/// 
/// Returns `true` if valid, `false` otherwise.
#[wasm_bindgen]
pub fn ed25519_verify(verifying_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<bool, JsValue> {
    let key_bytes: [u8; 32] = hex::decode(verifying_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid verifying key hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Verifying key must be 32 bytes"))?;

    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature hex: {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from_str("Signature must be 64 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid verifying key: {}", e)))?;
    let signature = Signature::from_bytes(&sig_bytes);

    Ok(verifying_key.verify(message, &signature).is_ok())
}

// ──────────────────────────────────────────────────────────────────────────────
// SHA-256 Hashing

/// Compute SHA-256 hash of data.
/// Returns hash as hex string (64 chars).
#[wasm_bindgen]
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ──────────────────────────────────────────────────────────────────────────────
// Double Ratchet Key Derivation Step 
// (matching our protocol crate design using HKDF chains)

/// Advance a symmetric chain key by one ratchet step.
/// 
/// Produces a new chain key and a message key:
///   message_key  = HKDF-SHA256(chain_key, salt=[], info="msg_key")
///   next_chain   = HKDF-SHA256(chain_key, salt=[], info="chain")
///
/// Returns JSON: `{ message_key: hex, next_chain_key: hex }`
#[wasm_bindgen]
pub fn ratchet_chain_step(chain_key_hex: &str) -> Result<String, JsValue> {
    let ck = hex::decode(chain_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid chain key hex: {}", e)))?;

    let msg_key_hex  = hkdf_sha256(&ck, &[], b"cyphra:msg_key:v1",  32)?;
    let next_ck_hex  = hkdf_sha256(&ck, &[], b"cyphra:chain_key:v1", 32)?;

    Ok(format!(
        r#"{{"message_key":"{}","next_chain_key":"{}"}}"#,
        msg_key_hex, next_ck_hex
    ))
}

/// Initialize a new ratchet root key from a shared DH secret.
/// 
/// Returns JSON `{ root_key: hex, chain_key: hex }`
#[wasm_bindgen]
pub fn ratchet_init_from_dh(dh_shared_hex: &str, prev_root_key_hex: &str) -> Result<String, JsValue> {
    let dh  = hex::decode(dh_shared_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid DH secret: {}", e)))?;
    let prk = hex::decode(prev_root_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid root key: {}", e)))?;

    let new_root  = hkdf_sha256(&dh, &prk, b"cyphra:root_key:v1",  32)?;
    let new_chain = hkdf_sha256(&dh, &prk, b"cyphra:chain_key:v1", 32)?;

    Ok(format!(
        r#"{{"root_key":"{}","chain_key":"{}"}}"#,
        new_root, new_chain
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Version / Health

#[wasm_bindgen]
pub fn cyphra_wasm_version() -> String {
    "cyphra-wasm@1.0.0 (AES-256-GCM + X25519 + Ed25519 + HKDF-SHA256)".to_string()
}
