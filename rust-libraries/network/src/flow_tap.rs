// Network flow capture and assembly

use cyphra_core::Result;
use std::collections::HashMap;

/// Flow identifier (5-tuple)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Flow statistics
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Flow tap for capturing packets
pub struct FlowTap {
    flows: HashMap<FlowKey, FlowStats>,
}

impl FlowTap {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Capture packet and update flow stats
    pub fn capture_packet(&mut self, key: FlowKey, size: u16, timestamp: u64) {
        let stats = self.flows.entry(key).or_insert(FlowStats {
            packet_count: 0,
            byte_count: 0,
            first_seen: timestamp,
            last_seen: timestamp,
        });
        
        stats.packet_count += 1;
        stats.byte_count += size as u64;
        stats.last_seen = timestamp;
    }

    /// Get flow statistics
    pub fn get_flow_stats(&self, key: &FlowKey) -> Option<&FlowStats> {
        self.flows.get(key)
    }

    /// Clear expired flows
    pub fn cleanup_expired(&mut self, current_time: u64, timeout: u64) {
        self.flows.retain(|_, stats| {
            current_time - stats.last_seen < timeout
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_tap() {
        let mut tap = FlowTap::new();
        let key = FlowKey {
            src_ip: [192, 168, 1, 1],
            dst_ip: [8, 8, 8, 8],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
        };
        
        tap.capture_packet(key.clone(), 100, 0);
        tap.capture_packet(key.clone(), 200, 10);
        
        let stats = tap.get_flow_stats(&key).unwrap();
        assert_eq!(stats.packet_count, 2);
        assert_eq!(stats.byte_count, 300);
    }
}
