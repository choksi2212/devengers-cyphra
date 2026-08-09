//! Route module — groups all endpoint handlers by domain.

pub mod crypto;
pub mod ai;
pub mod health;
pub mod db;

use axum::Router;
use crate::state::AppState;

/// Build the complete route tree.
pub fn build_routes() -> Router<AppState> {
    Router::new()
        .merge(health::routes())
        .nest("/crypto", crypto::routes())
        .nest("/ai", ai::routes())
        .nest("/db", db::routes())
}
