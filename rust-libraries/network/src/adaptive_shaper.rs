// Adaptive traffic shaping based on threat score

use crate::PaddingPolicy;
use std::time::Duration;

/// Adjust padding policy based on threat score
pub fn adjust_policy_by_threat(
    policy: &mut PaddingPolicy,
    threat_score: f32,
    bandwidth_budget: f32,
) {
    if threat_score > 0.7 {
        policy.rate = (policy.rate * 1.5).min(0.9);
        policy.timing_jitter = policy.timing_jitter * 2;
    } else if threat_score < 0.3 && policy.rate > 0.1 {
        policy.rate *= 0.8; // Reduce overhead
    }
    
    // Respect bandwidth budget
    if policy.rate * bandwidth_budget > policy.max_overhead {
        policy.rate = policy.max_overhead / bandwidth_budget;
    }
}

/// Measure overhead of current policy
pub fn measure_overhead(policy: &PaddingPolicy, baseline_bandwidth: f32) -> f32 {
    policy.rate * baseline_bandwidth
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_policy() {
        let mut policy = PaddingPolicy::default();
        let initial_rate = policy.rate;
        
        adjust_policy_by_threat(&mut policy, 0.8, 1.0);
        
        assert!(policy.rate > initial_rate);
    }
}
