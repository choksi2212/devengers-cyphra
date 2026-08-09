// Extract features from network flows for ML

use crate::flow_tap::FlowStats;

/// Extract packet size features
pub fn extract_packet_sizes(packets: &[(u16, u64)]) -> Vec<f32> {
    packets.iter().map(|(size, _)| *size as f32).collect()
}

/// Extract timing features
pub fn extract_timing(packets: &[(u16, u64)]) -> Vec<f32> {
    let mut timings = Vec::new();
    
    for i in 1..packets.len() {
        let iat = packets[i].1 - packets[i - 1].1;
        timings.push(iat as f32);
    }
    
    timings
}

/// Extract burst statistics
pub fn extract_burst_stats(packets: &[(u16, u64)]) -> (usize, f32, usize) {
    // TODO: Implement burst detection
    (0, 0.0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_timing() {
        let packets = vec![(100, 0), (200, 10), (150, 25)];
        let timings = extract_timing(&packets);
        
        assert_eq!(timings.len(), 2);
        assert_eq!(timings[0], 10.0);
        assert_eq!(timings[1], 15.0);
    }
}
