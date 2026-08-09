// Adaptive security policy engine

use cyphra_core::{SecurityPolicy, MissionPreset};
use std::time::Duration;

/// Adjust policy based on threat score
pub fn adjust_policy_by_threat(
    current_policy: &mut SecurityPolicy,
    threat_score: f32,
) {
    if threat_score > 0.8 {
        // CRITICAL: Maximum protection
        current_policy.ratchet_cadence = Duration::from_secs(60);
        current_policy.padding_rate = 0.9;
        current_policy.mix_path_length = 5;
        current_policy.destroy_on_read = true;
        current_policy.allow_p2p = false;
    } else if threat_score > 0.6 {
        // HIGH: Increased protection
        current_policy.ratchet_cadence = Duration::from_secs(300);
        current_policy.padding_rate = 0.6;
        current_policy.mix_path_length = 3;
    } else if threat_score > 0.4 {
        // MEDIUM: Balanced
        current_policy.ratchet_cadence = Duration::from_secs(3600);
        current_policy.padding_rate = 0.3;
        current_policy.mix_path_length = 2;
    } else {
        // LOW: Minimal overhead
        current_policy.ratchet_cadence = Duration::from_secs(7200);
        current_policy.padding_rate = 0.1;
        current_policy.mix_path_length = 1;
    }
}

/// Apply mission preset
pub fn apply_mission_preset(preset: MissionPreset) -> SecurityPolicy {
    preset.to_policy()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_policy() {
        let mut policy = SecurityPolicy::default();
        adjust_policy_by_threat(&mut policy, 0.9);
        
        assert_eq!(policy.mix_path_length, 5);
        assert!(policy.padding_rate > 0.8);
    }
}
