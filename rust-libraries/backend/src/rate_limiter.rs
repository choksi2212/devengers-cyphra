// Rate limiting and abuse prevention

use cyphra_core::{DeviceId, Result, Error};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use tokio::sync::RwLock;
use std::sync::Arc;

struct RateLimiter {
    counters: Arc<RwLock<HashMap<DeviceId, RateCounter>>>,
}

struct RateCounter {
    count: u32,
    window_start: SystemTime,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

static mut GLOBAL_LIMITER: Option<RateLimiter> = None;

fn get_limiter() -> &'static RateLimiter {
    unsafe {
        GLOBAL_LIMITER.get_or_insert_with(|| RateLimiter::new())
    }
}

/// Check rate limit
pub async fn check_rate_limit(device_id: DeviceId, limit: u32, window: Duration) -> Result<()> {
    let limiter = get_limiter();
    let mut counters = limiter.counters.write().await;
    
    let now = SystemTime::now();
    let counter = counters.entry(device_id).or_insert(RateCounter {
        count: 0,
        window_start: now,
    });
    
    // Reset counter if window expired
    if now.duration_since(counter.window_start).unwrap() > window {
        counter.count = 0;
        counter.window_start = now;
    }
    
    // Check limit
    if counter.count >= limit {
        return Err(Error::ProtocolError("Rate limit exceeded".to_string()));
    }
    
    counter.count += 1;
    Ok(())
}

/// Update rate limit counters
pub async fn update_counters(device_id: DeviceId) {
    let limiter = get_limiter();
    let mut counters = limiter.counters.write().await;
    
    if let Some(counter) = counters.get_mut(&device_id) {
        counter.count += 1;
    }
}
