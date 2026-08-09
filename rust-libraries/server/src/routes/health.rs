//! Health and status endpoints.

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    crates_loaded: Vec<&'static str>,
    crypto_backend: &'static str,
}

async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "cyphra-server",
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        crates_loaded: vec![
            "cyphra-core",
            "cyphra-protocol",
            "cyphra-ai",
            "cyphra-network",
            "cyphra-mixnet",
        ],
        crypto_backend: "libsodium + pqc_kyber (Kyber1024) + blake3",
    })
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(health_check))
}
