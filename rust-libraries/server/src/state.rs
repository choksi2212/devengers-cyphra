//! Shared application state
//!
//! Holds initialized resources that are shared across request handlers.

/// Application state shared across all request handlers via Axum's State extractor.
#[derive(Clone)]
pub struct AppState {
    /// Server start time for uptime reporting
    pub start_time: std::time::Instant,
}

impl AppState {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            start_time: std::time::Instant::now(),
        })
    }
}
