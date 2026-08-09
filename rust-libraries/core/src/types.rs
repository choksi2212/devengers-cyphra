use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Device identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

/// Message identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub [u8; 32]);

/// Conversation identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId(pub [u8; 32]);

/// Threat score (0.0 to 1.0)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThreatScore {
    pub overall: f32,
    pub confidence: f32,
    pub breakdown: ScoreBreakdown,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub network_anomaly: f32,
    pub behavioral_risk: f32,
    pub metadata_leak: f32,
    pub device_compromise: f32,
}

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub ratchet_cadence: Duration,
    pub padding_rate: f32,
    pub mix_path_length: usize,
    pub destroy_on_read: bool,
    pub allow_p2p: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            ratchet_cadence: Duration::from_secs(3600),
            padding_rate: 0.3,
            mix_path_length: 2,
            destroy_on_read: false,
            allow_p2p: true,
        }
    }
}

/// Mission presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionPreset {
    SilentPatrol,
    HotExtraction,
    SecureBase,
    CompromisedNetwork,
}

impl MissionPreset {
    pub fn to_policy(&self) -> SecurityPolicy {
        match self {
            MissionPreset::SilentPatrol => SecurityPolicy {
                ratchet_cadence: Duration::from_secs(1800),
                padding_rate: 0.8,
                mix_path_length: 4,
                destroy_on_read: true,
                allow_p2p: true,
            },
            MissionPreset::HotExtraction => SecurityPolicy {
                ratchet_cadence: Duration::from_secs(60),
                padding_rate: 0.95,
                mix_path_length: 5,
                destroy_on_read: true,
                allow_p2p: false,
            },
            MissionPreset::SecureBase => SecurityPolicy {
                ratchet_cadence: Duration::from_secs(7200),
                padding_rate: 0.2,
                mix_path_length: 1,
                destroy_on_read: false,
                allow_p2p: true,
            },
            MissionPreset::CompromisedNetwork => SecurityPolicy {
                ratchet_cadence: Duration::from_secs(300),
                padding_rate: 0.9,
                mix_path_length: 5,
                destroy_on_read: true,
                allow_p2p: false,
            },
        }
    }
}
