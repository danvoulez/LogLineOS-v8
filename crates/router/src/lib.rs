use logline_common::{Span, DerivedEvent};
use logline_hostcalls::{Hostcalls, HostcallError};
use logline_validators::validate_canonical;
use thiserror::Error;
use logline_trajectory::{link_open_or_continue};
use logline_quality::{trajectory_quality, quality_meter};

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("validation: {0}")]
    Validation(String),
    #[error(transparent)]
    Hostcall(#[from] HostcallError),
}

pub struct Router {
    host: Hostcalls,
}

impl Router {
    pub fn new(host: Hostcalls) -> Self { Self { host } }

    pub fn ingest(&self, span: &Span) -> Result<logline_common::Receipt, RouterError> {
        validate_canonical(span).map_err(|e| RouterError::Validation(e.to_string()))?;
        let receipt = self.host.ledger_append(span)?;
        // Derive: basic trajectory edge
        let edge = link_open_or_continue(&span.this, &span.tenant, &span.id, 1);
        let _ = self.host.emit_derived(&edge);
        // Derive: quality
        if let DerivedEvent::TrajectoryEdge { trajectory_id, .. } = edge {
            let q = trajectory_quality(&trajectory_id, &span.tenant);
            if let DerivedEvent::TrajectoryQuality { score, .. } = &q {
                let threshold = std::env::var("QUALITY_MIN_SCORE").ok().and_then(|v| v.parse::<i32>().ok()).unwrap_or(60);
                if let Some(cand) = quality_meter(&trajectory_id, *score, &span.tenant, threshold) {
                    let _ = self.host.emit_derived(&cand);
                }
            }
            let _ = self.host.emit_derived(&q);
        }
        Ok(receipt)
    }
}
