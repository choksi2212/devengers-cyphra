// On-device anomaly detector using GBDT ensemble

use cyphra_core::{Result, Error};
use serde::{Deserialize, Serialize};

/// Network flow features for ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub packet_sizes: Vec<u16>,
    pub inter_arrival_times: Vec<u64>,
    pub direction_pattern: Vec<bool>,
    pub burst_statistics: BurstStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstStats {
    pub burst_count: usize,
    pub avg_burst_size: f32,
    pub max_burst_size: usize,
    pub burst_duration: u64,
}

/// Anomaly detector
pub struct AnomalyDetector {
    ensemble: crate::gbdt_engine::Ensemble,
}

impl AnomalyDetector {
    /// Create new detector with trained model
    pub fn new(model_path: &str) -> Result<Self> {
        let ensemble = if model_path.is_empty() {
            // Use default empty ensemble if no path provided
            crate::gbdt_engine::Ensemble::default()
        } else {
            // Load trained GBDT model from JSON
            crate::gbdt_engine::Ensemble::load_from_json(model_path)
                .map_err(|e| Error::StorageError(format!("Failed to load model: {}", e)))?
        };
        
        Ok(Self { ensemble })
    }

    /// Extract features from network flow
    pub fn extract_features(&self, packets: &[Packet]) -> FlowFeatures {
        let packet_sizes: Vec<u16> = packets.iter().map(|p| p.size).collect();
        let inter_arrival_times: Vec<u64> = self.compute_inter_arrival_times(packets);
        let direction_pattern: Vec<bool> = packets.iter().map(|p| p.outgoing).collect();
        let burst_statistics = self.compute_burst_stats(packets);

        FlowFeatures {
            packet_sizes,
            inter_arrival_times,
            direction_pattern,
            burst_statistics,
        }
    }

    /// Compute threat score for flow
    pub fn compute_threat_score(&self, features: &FlowFeatures) -> f32 {
        // Convert features to vector
        let feature_vec = self.features_to_vector(features);
        
        // Run GBDT inference
        self.ensemble.predict(&feature_vec)
    }

    fn compute_inter_arrival_times(&self, packets: &[Packet]) -> Vec<u64> {
        let mut times = Vec::new();
        for i in 1..packets.len() {
            times.push(packets[i].timestamp - packets[i - 1].timestamp);
        }
        times
    }

    fn compute_burst_stats(&self, packets: &[Packet]) -> BurstStats {
        const BURST_THRESHOLD_US: u64 = 50_000; // 50ms threshold for burst detection
        
        if packets.len() < 2 {
            return BurstStats {
                burst_count: 0,
                avg_burst_size: 0.0,
                max_burst_size: 0,
                burst_duration: 0,
            };
        }
        
        let mut burst_count: usize = 0;
        let mut burst_sizes: Vec<usize> = Vec::new();
        let mut burst_durations: Vec<u64> = Vec::new();
        let mut in_burst = false;
        let mut current_burst_size: usize = 0;
        let mut current_burst_start: u64 = 0;
        
        for i in 1..packets.len() {
            let iat = packets[i].timestamp - packets[i - 1].timestamp;
            
            if iat < BURST_THRESHOLD_US {
                // Packets are close together - part of a burst
                if !in_burst {
                    in_burst = true;
                    current_burst_start = packets[i - 1].timestamp;
                    current_burst_size = 1;
                }
                current_burst_size += 1;
            } else if in_burst {
                // Burst ended
                burst_count += 1;
                burst_sizes.push(current_burst_size);
                burst_durations.push(packets[i - 1].timestamp - current_burst_start);
                in_burst = false;
                current_burst_size = 0;
            }
        }
        
        // Handle final burst if still in one
        if in_burst {
            burst_count += 1;
            burst_sizes.push(current_burst_size);
            if let Some(last) = packets.last() {
                burst_durations.push(last.timestamp - current_burst_start);
            }
        }
        
        let avg_burst_size = if burst_sizes.is_empty() {
            0.0
        } else {
            burst_sizes.iter().sum::<usize>() as f32 / burst_sizes.len() as f32
        };
        
        let max_burst_size = burst_sizes.iter().copied().max().unwrap_or(0);
        let total_burst_duration = burst_durations.iter().sum::<u64>();
        
        BurstStats {
            burst_count,
            avg_burst_size,
            max_burst_size,
            burst_duration: total_burst_duration,
        }
    }

    fn features_to_vector(&self, features: &FlowFeatures) -> Vec<f32> {
        let mut vec = Vec::new();
        
        // Statistical features from packet sizes
        if !features.packet_sizes.is_empty() {
            let mean = features.packet_sizes.iter().map(|&x| x as f32).sum::<f32>() 
                / features.packet_sizes.len() as f32;
            vec.push(mean);
            
            let max = *features.packet_sizes.iter().max().unwrap_or(&0) as f32;
            vec.push(max);
            
            let min = *features.packet_sizes.iter().min().unwrap_or(&0) as f32;
            vec.push(min);
        }
        
        // Timing features
        if !features.inter_arrival_times.is_empty() {
            let mean_iat = features.inter_arrival_times.iter().sum::<u64>() as f32 
                / features.inter_arrival_times.len() as f32;
            vec.push(mean_iat);
        }
        
        // Burst features
        vec.push(features.burst_statistics.burst_count as f32);
        vec.push(features.burst_statistics.avg_burst_size);
        
        // Direction ratio
        let outgoing_count = features.direction_pattern.iter().filter(|&&x| x).count();
        let direction_ratio = outgoing_count as f32 / features.direction_pattern.len() as f32;
        vec.push(direction_ratio);
        
        vec
    }
}

/// Packet representation
#[derive(Debug, Clone)]
pub struct Packet {
    pub size: u16,
    pub timestamp: u64,
    pub outgoing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extraction() {
        let packets = vec![
            Packet { size: 100, timestamp: 0, outgoing: true },
            Packet { size: 200, timestamp: 10, outgoing: false },
            Packet { size: 150, timestamp: 25, outgoing: true },
        ];
        
        let detector = AnomalyDetector::new("").unwrap();
        let features = detector.extract_features(&packets);
        
        assert_eq!(features.packet_sizes.len(), 3);
        assert_eq!(features.inter_arrival_times.len(), 2);
    }
}
