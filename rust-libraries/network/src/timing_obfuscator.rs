// Timing obfuscation and jitter injection

use std::time::Duration;
use tokio::time::sleep;
use rand::Rng;

/// Add random jitter to timing with proper random distribution
pub async fn add_jitter(jitter_range: Duration) {
    let mut rng = rand::thread_rng();
    let jitter_micros = rng.gen_range(0..jitter_range.as_micros() as u64);
    sleep(Duration::from_micros(jitter_micros)).await;
}

/// Apply timing jitter with specified maximum delay
pub async fn apply_timing_jitter(max_jitter: Duration) {
    let mut rng = rand::thread_rng();
    let jitter_ms = rng.gen_range(0..max_jitter.as_millis() as u64);
    sleep(Duration::from_millis(jitter_ms)).await;
}

/// Shape burst timing to avoid traffic analysis
pub async fn burst_shaping(packets: &mut [crate::Packet], target_rate: f32) {
    // Calculate inter-packet delay based on target rate
    let delay_micros = if target_rate > 0.0 {
        (1_000_000.0 / target_rate) as u64
    } else {
        1000 // Default 1ms
    };
    
    for packet in packets.iter_mut() {
        // Add base delay plus random jitter
        sleep(Duration::from_micros(delay_micros)).await;
        add_jitter(Duration::from_millis(5)).await;
    }
}

/// Schedule delayed transmission
pub async fn delay_scheduling(delay: Duration) {
    sleep(delay).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_jitter() {
        let start = std::time::Instant::now();
        add_jitter(Duration::from_millis(10)).await;
        let elapsed = start.elapsed();
        
        assert!(elapsed <= Duration::from_millis(11));
    }
}
