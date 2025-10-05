use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub id: String,
    pub tenant: String,
    pub who: String,
    pub did: String,
    pub this: String,
    pub when: String, // RFC3339 in wire format
    #[serde(default)]
    pub confirmed_by: Option<Vec<String>>,
    pub status: SpanStatus,
    #[serde(default)]
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpanStatus {
    Confirmed,
    Proposed,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityComponents {
    pub mass: i32,
    pub persistence: i32,
    pub verification: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DerivedEvent {
    #[serde(rename = "trajectory_edge")]
    TrajectoryEdge {
        trajectory_id: String,
        position: i32,
        src_span_id: String,
        this: String,
        tenant: String,
        ts: String,
    },
    #[serde(rename = "trajectory_closed")]
    TrajectoryClosed {
        trajectory_id: String,
        reason: String,
        tenant: String,
        ts: String,
    },
    #[serde(rename = "trajectory_quality")]
    TrajectoryQuality {
        trajectory_id: String,
        score: i32,
        components: QualityComponents,
        tenant: String,
        ts: String,
    },
    #[serde(rename = "diamond_candidate")]
    DiamondCandidate {
        trajectory_id: String,
        score: i32,
        threshold: i32,
        tenant: String,
        ts: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub op: String, // e.g., "ledger.append"
    pub span_id: String,
    pub tenant: String,
    pub jti: String,
    pub kid: String,
    pub sig: String,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemJson {
    #[serde(rename = "type")]
    pub type_url: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl ProblemJson {
    pub fn new(status: u16, title: impl Into<String>) -> Self {
        Self {
            type_url: "about:blank".to_string(),
            title: title.into(),
            status,
            detail: None,
            instance: None,
            trace_id: None,
        }
    }
}
