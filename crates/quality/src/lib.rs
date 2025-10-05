use chrono::Utc;
use logline_common::{DerivedEvent, QualityComponents};

pub fn trajectory_quality(trajectory_id: &str, tenant: &str) -> DerivedEvent {
    // naive deterministic score for M1
    let components = QualityComponents { mass: 30, persistence: 25, verification: 23 };
    let score = components.mass + components.persistence + components.verification;
    DerivedEvent::TrajectoryQuality {
        trajectory_id: trajectory_id.to_string(),
        score,
        components,
        tenant: tenant.to_string(),
        ts: Utc::now().to_rfc3339(),
    }
}

pub fn quality_meter(trajectory_id: &str, score: i32, tenant: &str, threshold: i32) -> Option<DerivedEvent> {
    if score >= threshold {
        Some(DerivedEvent::DiamondCandidate { trajectory_id: trajectory_id.to_string(), score, threshold, tenant: tenant.to_string(), ts: Utc::now().to_rfc3339() })
    } else {
        None
    }
}
