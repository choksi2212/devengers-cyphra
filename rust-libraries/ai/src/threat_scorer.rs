// Threat scoring engine combining multiple signals

use cyphra_core::{ThreatScore, ScoreBreakdown};
use std::time::SystemTime;

/// Threat signals from various sources
pub struct ThreatSignals {
    pub flow_features: crate::FlowFeatures,
    pub user_actions: Vec<UserAction>,
    pub traffic_pattern: TrafficPattern,
    pub device_state: DeviceState,
}

pub struct UserAction {
    pub action_type: String,
    pub timestamp: u64,
}

pub struct TrafficPattern {
    pub total_bytes: u64,
    pub connection_count: usize,
    pub unique_destinations: usize,
}

pub struct DeviceState {
    pub rooted: bool,
    pub debug_enabled: bool,
    pub unknown_sources: bool,
}

/// Compute comprehensive threat score
pub fn compute_threat_score(signals: &ThreatSignals) -> ThreatScore {
    // Network anomaly score (from GBDT)
    let network_score = 0.5; // Placeholder
    
    // Behavioral analysis
    let behavioral_score = analyze_behavior(&signals.user_actions);
    
    // Metadata leak detection
    let metadata_score = detect_metadata_leak(&signals.traffic_pattern);
    
    // Device integrity check
    let device_score = check_device_integrity(&signals.device_state);
    
    // Weighted aggregation
    let overall = 
        network_score * 0.3 +
        behavioral_score * 0.25 +
        metadata_score * 0.3 +
        device_score * 0.15;
    
    // Confidence based on signal quality
    let confidence = compute_confidence(signals);
    
    ThreatScore {
        overall,
        confidence,
        breakdown: ScoreBreakdown {
            network_anomaly: network_score,
            behavioral_risk: behavioral_score,
            metadata_leak: metadata_score,
            device_compromise: device_score,
        },
        timestamp: SystemTime::now(),
    }
}

fn analyze_behavior(actions: &[UserAction]) -> f32 {
    if actions.is_empty() {
        return 0.0;
    }
    
    let mut score: f32 = 0.0;
    
    // Check action frequency (actions per minute)
    if actions.len() >= 2 {
        let span = actions.last().unwrap().timestamp - actions.first().unwrap().timestamp;
        if span > 0 {
            let apm = (actions.len() as f64 / span as f64) * 60_000_000.0; // Convert to APM
            if apm > 60.0 {
                score += 0.3; // Suspiciously high activity
            }
        }
    }
    
    // Check rapid successive actions (bot-like behavior)
    let rapid_actions = actions.windows(2)
        .filter(|w| w[1].timestamp - w[0].timestamp < 100)
        .count();
    if rapid_actions > 5 {
        score += 0.3;
    }
    
    // Check for enumeration behavior (many different action types)
    let unique_types: std::collections::HashSet<_> = actions.iter()
        .map(|a| &a.action_type)
        .collect();
    if unique_types.len() > 20 {
        score += 0.2;
    }
    
    score.min(1.0)
}

fn detect_metadata_leak(pattern: &TrafficPattern) -> f32 {
    let mut score: f32 = 0.0;
    
    // High number of unique destinations
    if pattern.unique_destinations > 50 {
        score += 0.3;
    }
    
    // Large data transfer
    if pattern.total_bytes > 100_000_000 { // 100MB
        score += 0.3;
    }
    
    // High connection count
    if pattern.connection_count > 100 {
        score += 0.2;
    }
    
    // Connection to destination ratio (potential scanning)
    if pattern.unique_destinations > 0 && pattern.connection_count > 0 {
        let ratio = pattern.connection_count as f32 / pattern.unique_destinations as f32;
        if ratio > 10.0 {
            score += 0.2; // Many connections to few destinations
        }
    }
    
    score.min(1.0)
}

fn check_device_integrity(state: &DeviceState) -> f32 {
    let mut score: f32 = 0.0;
    
    if state.rooted {
        score += 0.5;
    }
    if state.debug_enabled {
        score += 0.3;
    }
    if state.unknown_sources {
        score += 0.2;
    }
    
    score.min(1.0)
}

fn compute_confidence(signals: &ThreatSignals) -> f32 {
    let mut confidence: f32 = 1.0;
    
    // Reduce confidence if we have insufficient data
    if signals.flow_features.packet_sizes.len() < 10 {
        confidence -= 0.3;
    }
    
    if signals.user_actions.is_empty() {
        confidence -= 0.2;
    }
    
    if signals.traffic_pattern.total_bytes == 0 {
        confidence -= 0.2;
    }
    
    if signals.flow_features.inter_arrival_times.is_empty() {
        confidence -= 0.1;
    }
    
    confidence.max(0.1).min(1.0)
}
