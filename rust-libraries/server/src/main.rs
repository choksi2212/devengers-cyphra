//! CYPHRA REST API Server
//!
//! Exposes all in-house cryptographic library functions over HTTP.
//! This is a thin server wrapper — zero modifications to any library crate.
//!
//! Architecture:
//!   Browser → Node.js :3001 → proxy → this server :5050
//!
//! Endpoints:
//!   POST /api/v1/crypto/keypair/identity     — Generate Kyber1024 + X25519 identity keypair
//!   POST /api/v1/crypto/keypair/signed       — Generate signed prekey
//!   POST /api/v1/crypto/keypair/onetime      — Generate one-time prekeys
//!   POST /api/v1/crypto/x3dh/initiate        — Initiate X3DH session
//!   POST /api/v1/crypto/x3dh/accept          — Accept X3DH session
//!   POST /api/v1/crypto/hkdf                  — HKDF-BLAKE3 key derivation
//!   POST /api/v1/crypto/hash                  — BLAKE3 hash
//!   POST /api/v1/ai/threat-score             — Compute comprehensive threat score
//!   POST /api/v1/ai/anomaly-detect           — Anomaly detection on flow features
//!   GET  /api/v1/health                       — Liveness check

mod routes;
mod state;

use axum::Router;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cyphra_server=info,tower_http=info".into()),
        )
        .init();

    // Initialize libsodium (required before any crypto operations)
    cyphra_core::init_libsodium()
        .expect("FATAL: Failed to initialize libsodium");
    tracing::info!("✓ libsodium initialized");

    // Build shared application state
    let state = AppState::new()?;
    tracing::info!("✓ Application state initialized");

    // Build router
    let app = Router::new()
        .nest("/api/v1", routes::build_routes())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Bind and serve
    let port: u16 = std::env::var("CYPHRA_PORT")
        .unwrap_or_else(|_| "5050".to_string())
        .parse()
        .unwrap_or(5050);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("═══════════════════════════════════════════════════════");
    tracing::info!("  CYPHRA Crypto API Server");
    tracing::info!("  Listening on http://{}", addr);
    tracing::info!("  Crates: core + protocol + ai + network + mixnet");
    tracing::info!("═══════════════════════════════════════════════════════");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
