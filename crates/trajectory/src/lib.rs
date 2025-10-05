use chrono::Utc;
use logline_common::DerivedEvent;

pub fn link_open_or_continue(this: &str, tenant: &str, src_span_id: &str, position: i32) -> DerivedEvent {
    DerivedEvent::TrajectoryEdge {
        trajectory_id: format!("t_{}", this),
        position,
        src_span_id: src_span_id.to_string(),
        this: this.to_string(),
        tenant: tenant.to_string(),
        ts: Utc::now().to_rfc3339(),
    }
}

pub fn close_by_timeout_or_rule(trajectory_id: &str, tenant: &str, reason: &str) -> DerivedEvent {
    DerivedEvent::TrajectoryClosed {
        trajectory_id: trajectory_id.to_string(),
        reason: reason.to_string(),
        tenant: tenant.to_string(),
        ts: Utc::now().to_rfc3339(),
    }
}
