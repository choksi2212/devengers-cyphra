// Feature engineering for traffic analysis

/// Compute statistical features
pub fn compute_statistical_features(values: &[f32]) -> Vec<f32> {
    if values.is_empty() {
        return vec![0.0; 5];
    }
    
    let mean = values.iter().sum::<f32>() / values.len() as f32;
    let max = values.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let min = values.iter().cloned().fold(f32::INFINITY, f32::min);
    
    let variance = values.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f32>() / values.len() as f32;
    let std_dev = variance.sqrt();
    
    vec![mean, max, min, std_dev, variance]
}

/// Compute burst features
pub fn compute_burst_features(packet_sizes: &[u16], timestamps: &[u64]) -> Vec<f32> {
    // TODO: Implement burst detection
    vec![0.0; 3]
}

/// Compute ratio features
pub fn compute_ratio_features(outgoing: &[bool]) -> Vec<f32> {
    if outgoing.is_empty() {
        return vec![0.0; 2];
    }
    
    let outgoing_count = outgoing.iter().filter(|&&x| x).count() as f32;
    let total = outgoing.len() as f32;
    let outgoing_ratio = outgoing_count / total;
    let incoming_ratio = 1.0 - outgoing_ratio;
    
    vec![outgoing_ratio, incoming_ratio]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistical_features() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let features = compute_statistical_features(&values);
        
        assert_eq!(features[0], 3.0); // mean
        assert_eq!(features[1], 5.0); // max
        assert_eq!(features[2], 1.0); // min
    }
}
