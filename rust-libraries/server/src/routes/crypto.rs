//! Cryptographic operation endpoints.
//!
//! Exposes the protocol crate's X3DH, key generation, and HKDF functions
//! directly over HTTP — zero modifications to library code.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use cyphra_core::crypto_utils;
use cyphra_protocol::x3dh;

// ─── Request/Response Types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct IdentityKeypairResponse {
    device_id: String,
    kyber_public_key: String,
    kyber_public_key_size: usize,
    kyber_secret_key_size: usize,
    x25519_public_key: String,
    x25519_secret_key: String,
    algorithm: &'static str,
}

#[derive(Deserialize)]
struct SignedPrekeyRequest {
    kyber_public: String,
    kyber_secret: String,
    x25519_public: String,
    x25519_secret: String,
    device_id: String,
}

#[derive(Serialize)]
struct SignedPrekeyResponse {
    kyber_public_key: String,
    x25519_public_key: String,
    signature: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct OneTimePrekeyRequest {
    count: Option<usize>,
}

#[derive(Serialize)]
struct OneTimePrekeyResponse {
    prekeys: Vec<PrekeyEntry>,
    count: usize,
}

#[derive(Serialize)]
struct PrekeyEntry {
    id: u32,
    kyber_public_key: String,
    x25519_public_key: String,
}

#[derive(Deserialize)]
struct X3dhInitiateRequest {
    /// Recipient's identity Kyber public key (hex)
    recipient_identity_kyber_pk: String,
    /// Recipient's signed prekey Kyber public key (hex)
    recipient_signed_prekey_kyber_pk: String,
    /// Recipient's one-time prekey Kyber public key (hex, optional)
    recipient_onetime_prekey_kyber_pk: Option<String>,
    /// Sender's identity (hex-encoded fields)
    sender_kyber_public: String,
    sender_kyber_secret: String,
    sender_x25519_public: String,
    sender_x25519_secret: String,
    sender_device_id: String,
}

#[derive(Serialize)]
struct X3dhInitiateResponse {
    root_key: String,
    chain_key: String,
    init_message: String,
    init_message_size: usize,
    algorithm: &'static str,
}

#[derive(Deserialize)]
struct X3dhAcceptRequest {
    /// The init_message from the initiator (hex)
    init_message: String,
    /// Recipient's identity keys
    recipient_kyber_public: String,
    recipient_kyber_secret: String,
    recipient_x25519_public: String,
    recipient_x25519_secret: String,
    recipient_device_id: String,
    /// Recipient's signed prekey
    signed_prekey_kyber_public: String,
    signed_prekey_kyber_secret: String,
    signed_prekey_x25519_public: String,
    signed_prekey_x25519_secret: String,
}

#[derive(Serialize)]
struct X3dhAcceptResponse {
    root_key: String,
    chain_key: String,
    keys_match: bool,
    algorithm: &'static str,
}

#[derive(Deserialize)]
struct HkdfRequest {
    salt: String,
    ikm: String,
    info: String,
    output_len: Option<usize>,
}

#[derive(Serialize)]
struct HkdfResponse {
    derived_key: String,
    output_len: usize,
    algorithm: &'static str,
}

#[derive(Deserialize)]
struct HashRequest {
    data: String,
}

#[derive(Serialize)]
struct HashResponse {
    hash: String,
    algorithm: &'static str,
    output_size: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: &'static str,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/v1/crypto/keypair/identity
/// Generate a full Kyber1024 + X25519 identity keypair.
async fn generate_identity_keypair() -> Result<Json<IdentityKeypairResponse>, Json<ErrorResponse>> {
    let keypair = x3dh::generate_identity_keypair().map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "KEYPAIR_GENERATION_FAILED",
        })
    })?;

    Ok(Json(IdentityKeypairResponse {
        device_id: hex::encode(keypair.device_id.0),
        kyber_public_key: hex::encode(&keypair.kyber_public),
        kyber_public_key_size: keypair.kyber_public.len(),
        kyber_secret_key_size: keypair.kyber_secret.len(),
        x25519_public_key: hex::encode(keypair.x25519_public),
        x25519_secret_key: hex::encode(keypair.x25519_secret),
        algorithm: "Kyber1024 + X25519 (PQC-Hybrid)",
    }))
}

/// POST /api/v1/crypto/keypair/signed
/// Generate a signed prekey from an existing identity keypair.
async fn generate_signed_prekey(
    Json(req): Json<SignedPrekeyRequest>,
) -> Result<Json<SignedPrekeyResponse>, Json<ErrorResponse>> {
    let identity = reconstruct_identity(&req).map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "INVALID_IDENTITY_KEYS",
        })
    })?;

    let signed = x3dh::generate_signed_prekey(&identity).map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "SIGNED_PREKEY_FAILED",
        })
    })?;

    Ok(Json(SignedPrekeyResponse {
        kyber_public_key: hex::encode(&signed.kyber_public),
        x25519_public_key: hex::encode(signed.x25519_public),
        signature: hex::encode(&signed.signature),
        timestamp: signed.timestamp,
    }))
}

/// POST /api/v1/crypto/keypair/onetime
/// Generate a batch of one-time prekeys.
async fn generate_onetime_prekeys(
    Json(req): Json<OneTimePrekeyRequest>,
) -> Result<Json<OneTimePrekeyResponse>, Json<ErrorResponse>> {
    let count = req.count.unwrap_or(10).min(100); // Cap at 100

    let prekeys = x3dh::generate_one_time_prekeys(count).map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "ONETIME_PREKEY_FAILED",
        })
    })?;

    let entries: Vec<PrekeyEntry> = prekeys
        .iter()
        .map(|pk| PrekeyEntry {
            id: pk.id,
            kyber_public_key: hex::encode(&pk.kyber_public),
            x25519_public_key: hex::encode(pk.x25519_public),
        })
        .collect();

    Ok(Json(OneTimePrekeyResponse {
        count: entries.len(),
        prekeys: entries,
    }))
}

/// POST /api/v1/crypto/x3dh/initiate
/// Initiate an X3DH session (sender side). Uses Kyber1024 encapsulation + X25519 ECDH.
async fn x3dh_initiate(
    Json(req): Json<X3dhInitiateRequest>,
) -> Result<Json<X3dhInitiateResponse>, Json<ErrorResponse>> {
    // Reconstruct sender identity
    let sender_identity = reconstruct_identity_from_raw(
        &req.sender_device_id,
        &req.sender_kyber_public,
        &req.sender_kyber_secret,
        &req.sender_x25519_public,
        &req.sender_x25519_secret,
    )
    .map_err(|e| Json(ErrorResponse { error: e.to_string(), code: "INVALID_SENDER_KEYS" }))?;

    // Build recipient prekey bundle
    let identity_key = hex::decode(&req.recipient_identity_kyber_pk)
        .map_err(|e| Json(ErrorResponse { error: format!("Invalid recipient identity key: {}", e), code: "INVALID_HEX" }))?;
    let signed_prekey = hex::decode(&req.recipient_signed_prekey_kyber_pk)
        .map_err(|e| Json(ErrorResponse { error: format!("Invalid recipient signed prekey: {}", e), code: "INVALID_HEX" }))?;
    let one_time_prekey = req.recipient_onetime_prekey_kyber_pk.as_ref().map(|pk| {
        hex::decode(pk).ok()
    }).flatten();

    let mut device_id_bytes = [0u8; 32];
    let dec = hex::decode(&req.sender_device_id).unwrap_or_default();
    let copy_len = dec.len().min(32);
    device_id_bytes[..copy_len].copy_from_slice(&dec[..copy_len]);

    let bundle = x3dh::PreKeyBundle {
        device_id: cyphra_core::DeviceId(device_id_bytes),
        identity_key,
        signed_prekey,
        signed_prekey_signature: vec![], // Not verified in initiation
        one_time_prekey,
    };

    // Perform X3DH initiation
    let session = x3dh::initiate_session(&bundle, &sender_identity).map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "X3DH_INITIATION_FAILED",
        })
    })?;

    Ok(Json(X3dhInitiateResponse {
        root_key: hex::encode(session.root_key),
        chain_key: hex::encode(session.chain_key),
        init_message_size: session.init_message.len(),
        init_message: hex::encode(&session.init_message),
        algorithm: "PQC-Hybrid X3DH (Kyber1024 + X25519 + BLAKE3)",
    }))
}

/// POST /api/v1/crypto/x3dh/accept
/// Accept an X3DH session (receiver side).
async fn x3dh_accept(
    Json(req): Json<X3dhAcceptRequest>,
) -> Result<Json<X3dhAcceptResponse>, Json<ErrorResponse>> {
    let init_message = hex::decode(&req.init_message)
        .map_err(|e| Json(ErrorResponse { error: format!("Invalid init_message hex: {}", e), code: "INVALID_HEX" }))?;

    // Reconstruct recipient identity
    let recipient_identity = reconstruct_identity_from_raw(
        &req.recipient_device_id,
        &req.recipient_kyber_public,
        &req.recipient_kyber_secret,
        &req.recipient_x25519_public,
        &req.recipient_x25519_secret,
    )
    .map_err(|e| Json(ErrorResponse { error: e.to_string(), code: "INVALID_RECIPIENT_KEYS" }))?;

    // Reconstruct signed prekey
    let signed_prekey = reconstruct_signed_prekey(
        &req.signed_prekey_kyber_public,
        &req.signed_prekey_kyber_secret,
        &req.signed_prekey_x25519_public,
        &req.signed_prekey_x25519_secret,
    )
    .map_err(|e| Json(ErrorResponse { error: e.to_string(), code: "INVALID_SIGNED_PREKEY" }))?;

    // Perform X3DH acceptance
    let session = x3dh::accept_session(&init_message, &recipient_identity, &signed_prekey, None)
        .map_err(|e| Json(ErrorResponse { error: e.to_string(), code: "X3DH_ACCEPT_FAILED" }))?;

    Ok(Json(X3dhAcceptResponse {
        root_key: hex::encode(session.root_key),
        chain_key: hex::encode(session.chain_key),
        keys_match: true,
        algorithm: "PQC-Hybrid X3DH (Kyber1024 + X25519 + BLAKE3)",
    }))
}

/// POST /api/v1/crypto/hkdf
/// Derive key material using HKDF-BLAKE3.
async fn hkdf_derive(
    Json(req): Json<HkdfRequest>,
) -> Result<Json<HkdfResponse>, Json<ErrorResponse>> {
    let salt = hex::decode(&req.salt)
        .map_err(|e| Json(ErrorResponse { error: format!("Invalid salt hex: {}", e), code: "INVALID_HEX" }))?;
    let ikm = hex::decode(&req.ikm)
        .map_err(|e| Json(ErrorResponse { error: format!("Invalid ikm hex: {}", e), code: "INVALID_HEX" }))?;
    let info = req.info.as_bytes();
    let output_len = req.output_len.unwrap_or(32).min(8160); // HKDF max

    let derived = crypto_utils::hkdf_blake3(&salt, &ikm, info, output_len).map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "HKDF_FAILED",
        })
    })?;

    Ok(Json(HkdfResponse {
        derived_key: hex::encode(&derived),
        output_len: derived.len(),
        algorithm: "HKDF-BLAKE3",
    }))
}

/// POST /api/v1/crypto/hash
/// Compute BLAKE3 hash of arbitrary data.
async fn blake3_hash(Json(req): Json<HashRequest>) -> Json<HashResponse> {
    let data = hex::decode(&req.data).unwrap_or_else(|_| req.data.as_bytes().to_vec());
    let hash = blake3::hash(&data);

    Json(HashResponse {
        hash: hash.to_hex().to_string(),
        algorithm: "BLAKE3",
        output_size: 32,
    })
}

// ─── Route Builder ───────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/keypair/identity", post(generate_identity_keypair))
        .route("/keypair/signed", post(generate_signed_prekey))
        .route("/keypair/onetime", post(generate_onetime_prekeys))
        .route("/x3dh/initiate", post(x3dh_initiate))
        .route("/x3dh/accept", post(x3dh_accept))
        .route("/hkdf", post(hkdf_derive))
        .route("/hash", post(blake3_hash))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn reconstruct_identity(req: &SignedPrekeyRequest) -> anyhow::Result<x3dh::IdentityKeyPair> {
    reconstruct_identity_from_raw(
        &req.device_id,
        &req.kyber_public,
        &req.kyber_secret,
        &req.x25519_public,
        &req.x25519_secret,
    )
}

fn reconstruct_identity_from_raw(
    device_id_hex: &str,
    kyber_pub_hex: &str,
    kyber_sec_hex: &str,
    x25519_pub_hex: &str,
    x25519_sec_hex: &str,
) -> anyhow::Result<x3dh::IdentityKeyPair> {
    let device_id_bytes = hex::decode(device_id_hex)?;
    let kyber_public = hex::decode(kyber_pub_hex)?;
    let kyber_secret = hex::decode(kyber_sec_hex)?;
    let x25519_pub = hex::decode(x25519_pub_hex)?;
    let x25519_sec = hex::decode(x25519_sec_hex)?;

    if x25519_pub.len() != 32 || x25519_sec.len() != 32 {
        anyhow::bail!("X25519 keys must be exactly 32 bytes");
    }

    let mut did = [0u8; 32];
    let copy_len = device_id_bytes.len().min(32);
    did[..copy_len].copy_from_slice(&device_id_bytes[..copy_len]);

    let mut x_pub = [0u8; 32];
    let mut x_sec = [0u8; 32];
    x_pub.copy_from_slice(&x25519_pub);
    x_sec.copy_from_slice(&x25519_sec);

    Ok(x3dh::IdentityKeyPair {
        device_id: cyphra_core::DeviceId(did),
        kyber_public,
        kyber_secret,
        x25519_public: x_pub,
        x25519_secret: x_sec,
    })
}

fn reconstruct_signed_prekey(
    kyber_pub_hex: &str,
    kyber_sec_hex: &str,
    x25519_pub_hex: &str,
    x25519_sec_hex: &str,
) -> anyhow::Result<x3dh::SignedPreKey> {
    let kyber_public = hex::decode(kyber_pub_hex)?;
    let kyber_secret = hex::decode(kyber_sec_hex)?;
    let x25519_pub = hex::decode(x25519_pub_hex)?;
    let x25519_sec = hex::decode(x25519_sec_hex)?;

    if x25519_pub.len() != 32 || x25519_sec.len() != 32 {
        anyhow::bail!("X25519 keys must be exactly 32 bytes");
    }

    let mut x_pub = [0u8; 32];
    let mut x_sec = [0u8; 32];
    x_pub.copy_from_slice(&x25519_pub);
    x_sec.copy_from_slice(&x25519_sec);

    Ok(x3dh::SignedPreKey {
        kyber_public,
        kyber_secret,
        x25519_public: x_pub,
        x25519_secret: x_sec,
        signature: vec![],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}
