//! AI/ML threat analysis endpoints.
//!
//! Exposes the `cyphra-ai` crate's anomaly detection and threat scoring
//! over HTTP — zero modifications to library code.

use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use cyphra_ai::{
    anomaly_detector::{AnomalyDetector, FlowFeatures, BurstStats, Packet},
    threat_scorer::{self, ThreatSignals, TrafficPattern, DeviceState, UserAction},
};

// ─── Request/Response Types ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct ThreatScoreRequest {
    /// Packet sizes observed in the flow
    packet_sizes: Vec<u16>,
    /// Inter-arrival times in microseconds
    inter_arrival_times: Vec<u64>,
    /// Direction pattern (true = outgoing, false = incoming)
    direction_pattern: Vec<bool>,
    /// Traffic pattern metadata
    total_bytes: Option<u64>,
    connection_count: Option<usize>,
    unique_destinations: Option<usize>,
    /// Device state
    rooted: Option<bool>,
    debug_enabled: Option<bool>,
    unknown_sources: Option<bool>,
    /// User actions (for behavioral analysis)
    user_actions: Option<Vec<UserActionInput>>,
}

#[derive(Deserialize)]
struct UserActionInput {
    action_type: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ThreatScoreResponse {
    overall_score: f32,
    confidence: f32,
    breakdown: BreakdownResponse,
    classification: &'static str,
    recommendation: &'static str,
}

#[derive(Serialize)]
struct BreakdownResponse {
    network_anomaly: f32,
    behavioral_risk: f32,
    metadata_leak: f32,
    device_compromise: f32,
}

#[derive(Deserialize)]
struct AnomalyDetectRequest {
    /// Raw packet data for feature extraction
    packets: Vec<PacketInput>,
}

#[derive(Deserialize)]
struct PacketInput {
    size: u16,
    timestamp: u64,
    outgoing: bool,
}

#[derive(Serialize)]
struct AnomalyDetectResponse {
    threat_score: f32,
    features_extracted: FeaturesSummary,
    classification: &'static str,
}

#[derive(Serialize)]
struct FeaturesSummary {
    packet_count: usize,
    mean_packet_size: f32,
    max_packet_size: u16,
    mean_iat_us: f64,
    burst_count: usize,
    avg_burst_size: f32,
    outgoing_ratio: f32,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: &'static str,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// POST /api/v1/ai/threat-score
/// Compute comprehensive multi-signal threat score.
async fn compute_threat_score(
    Json(req): Json<ThreatScoreRequest>,
) -> Result<Json<ThreatScoreResponse>, Json<ErrorResponse>> {
    // Build flow features
    let flow_features = FlowFeatures {
        packet_sizes: req.packet_sizes,
        inter_arrival_times: req.inter_arrival_times,
        direction_pattern: req.direction_pattern,
        burst_statistics: BurstStats {
            burst_count: 0,
            avg_burst_size: 0.0,
            max_burst_size: 0,
            burst_duration: 0,
        },
    };

    // Build traffic pattern
    let traffic_pattern = TrafficPattern {
        total_bytes: req.total_bytes.unwrap_or(0),
        connection_count: req.connection_count.unwrap_or(0),
        unique_destinations: req.unique_destinations.unwrap_or(0),
    };

    // Build device state
    let device_state = DeviceState {
        rooted: req.rooted.unwrap_or(false),
        debug_enabled: req.debug_enabled.unwrap_or(false),
        unknown_sources: req.unknown_sources.unwrap_or(false),
    };

    // Build user actions
    let user_actions: Vec<UserAction> = req
        .user_actions
        .unwrap_or_default()
        .into_iter()
        .map(|a| UserAction {
            action_type: a.action_type,
            timestamp: a.timestamp,
        })
        .collect();

    // Compute threat score via the AI crate
    let signals = ThreatSignals {
        flow_features,
        user_actions,
        traffic_pattern,
        device_state,
    };

    let score = threat_scorer::compute_threat_score(&signals);

    // Classify
    let (classification, recommendation) = classify_threat(score.overall);

    Ok(Json(ThreatScoreResponse {
        overall_score: score.overall,
        confidence: score.confidence,
        breakdown: BreakdownResponse {
            network_anomaly: score.breakdown.network_anomaly,
            behavioral_risk: score.breakdown.behavioral_risk,
            metadata_leak: score.breakdown.metadata_leak,
            device_compromise: score.breakdown.device_compromise,
        },
        classification,
        recommendation,
    }))
}

/// POST /api/v1/ai/anomaly-detect
/// Run anomaly detection on raw packet data using the GBDT engine.
async fn anomaly_detect(
    Json(req): Json<AnomalyDetectRequest>,
) -> Result<Json<AnomalyDetectResponse>, Json<ErrorResponse>> {
    if req.packets.is_empty() {
        return Err(Json(ErrorResponse {
            error: "At least one packet is required".to_string(),
            code: "EMPTY_PACKETS",
        }));
    }

    // Convert to internal Packet type
    let packets: Vec<Packet> = req
        .packets
        .iter()
        .map(|p| Packet {
            size: p.size,
            timestamp: p.timestamp,
            outgoing: p.outgoing,
        })
        .collect();

    // Create detector (using empty model path — uses built-in heuristics)
    let detector = AnomalyDetector::new("").map_err(|e| {
        Json(ErrorResponse {
            error: e.to_string(),
            code: "DETECTOR_INIT_FAILED",
        })
    })?;

    // Extract features
    let features = detector.extract_features(&packets);

    // Compute threat score
    let threat_score = detector.compute_threat_score(&features);

    // Build summary
    let mean_pkt_size = if features.packet_sizes.is_empty() {
        0.0
    } else {
        features.packet_sizes.iter().map(|&s| s as f32).sum::<f32>()
            / features.packet_sizes.len() as f32
    };

    let max_pkt_size = features.packet_sizes.iter().copied().max().unwrap_or(0);

    let mean_iat = if features.inter_arrival_times.is_empty() {
        0.0
    } else {
        features.inter_arrival_times.iter().sum::<u64>() as f64
            / features.inter_arrival_times.len() as f64
    };

    let outgoing_count = features.direction_pattern.iter().filter(|&&x| x).count();
    let outgoing_ratio = if features.direction_pattern.is_empty() {
        0.0
    } else {
        outgoing_count as f32 / features.direction_pattern.len() as f32
    };

    let (classification, _) = classify_threat(threat_score);

    Ok(Json(AnomalyDetectResponse {
        threat_score,
        features_extracted: FeaturesSummary {
            packet_count: packets.len(),
            mean_packet_size: mean_pkt_size,
            max_packet_size: max_pkt_size,
            mean_iat_us: mean_iat,
            burst_count: features.burst_statistics.burst_count,
            avg_burst_size: features.burst_statistics.avg_burst_size,
            outgoing_ratio,
        },
        classification,
    }))
}

// ─── Route Builder ───────────────────────────────────────────────────────────

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/threat-score", post(compute_threat_score))
        .route("/anomaly-detect", post(anomaly_detect))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn classify_threat(score: f32) -> (&'static str, &'static str) {
    if score < 0.25 {
        ("Normal", "No action required.")
    } else if score < 0.50 {
        ("Elevated", "Increase monitoring frequency.")
    } else if score < 0.75 {
        ("High", "Review traffic patterns and apply rate limits.")
    } else {
        ("Critical", "Immediate response required. Block and investigate.")
    }
}
