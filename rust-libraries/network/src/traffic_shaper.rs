// Traffic shaper and padding engine

use cyphra_core::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Padding policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingPolicy {
    pub rate: f32,
    pub max_overhead: f32,
    pub timing_jitter: Duration,
    pub cover_rate: f32,
}

impl Default for PaddingPolicy {
    fn default() -> Self {
        Self {
            rate: 0.3,
            max_overhead: 0.5,
            timing_jitter: Duration::from_millis(50),
            cover_rate: 0.1,
        }
    }
}

/// Network packet
#[derive(Debug, Clone)]
pub struct Packet {
    pub data: Vec<u8>,
    pub timestamp: u64,
}

impl Packet {
    /// Append padding to packet
    pub fn append_padding(&mut self, size: usize) {
        self.data.extend(vec![0u8; size]);
    }

    /// Fragment packet if too large
    pub fn fragment(&mut self, target_size: usize) -> Vec<Packet> {
        let mut fragments = Vec::new();
        let mut offset = 0;
        
        while offset < self.data.len() {
            let end = (offset + target_size).min(self.data.len());
            fragments.push(Packet {
                data: self.data[offset..end].to_vec(),
                timestamp: self.timestamp,
            });
            offset = end;
        }
        
        fragments
    }
}

/// Apply adaptive padding to packet
pub fn apply_adaptive_padding(
    packet: &mut Packet,
    threat_score: f32,
    policy: &mut PaddingPolicy,
) -> Result<()> {
    // Increase padding rate with threat score
    policy.rate = (threat_score * 0.5).min(0.8);
    
    // Calculate padding size
    let padding_size = sample_padding_distribution(policy.rate);
    
    // Add padding bytes
    packet.append_padding(padding_size);
    
    Ok(())
}

/// Morph packet size to target
pub fn morph_packet_size(packet: &mut Packet, target_size: usize) {
    if packet.data.len() < target_size {
        packet.append_padding(target_size - packet.data.len());
    }
}

/// Sample padding size from exponential distribution
fn sample_padding_distribution(rate: f32) -> usize {
    use rand::Rng;
    
    let mut rng = rand::thread_rng();
    
    // Mean padding size based on rate (scaled to typical packet sizes)
    let mean = (rate * 1500.0).max(1.0); // 1500 bytes = typical MTU
    
    // Lambda parameter for exponential distribution
    let lambda = 1.0 / mean;
    
    // Sample from uniform distribution [0, 1)
    let u: f32 = rng.gen_range(0.001..1.0);
    
    // Inverse transform sampling for exponential distribution
    // X = -ln(U) / lambda
    let sample = -u.ln() / lambda;
    
    // Round and ensure non-negative
    sample.round().max(0.0) as usize
}

/// Generate dummy packet for cover traffic
pub fn generate_dummy_packet() -> Packet {
    Packet {
        data: vec![0u8; 100],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        let mut packet = Packet {
            data: vec![1, 2, 3],
            timestamp: 0,
        };
        
        packet.append_padding(5);
        assert_eq!(packet.data.len(), 8);
    }

    #[test]
    fn test_morph_packet_size() {
        let mut packet = Packet {
            data: vec![1, 2, 3],
            timestamp: 0,
        };
        
        morph_packet_size(&mut packet, 10);
        assert_eq!(packet.data.len(), 10);
    }
}
