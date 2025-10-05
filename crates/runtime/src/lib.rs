use chrono::Utc;
use logline_common::{Receipt, Span};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

pub trait Ledger {
    fn append(&self, span: &Span) -> Result<Receipt, LedgerError>;
}

pub struct FileLedger {
    base_dir: std::path::PathBuf,
}

impl FileLedger {
    pub fn new(base_dir: impl Into<std::path::PathBuf>) -> Self {
        Self { base_dir: base_dir.into() }
    }
}

impl Ledger for FileLedger {
    fn append(&self, span: &Span) -> Result<Receipt, LedgerError> {
        let segments_dir = self.base_dir.join("ledger").join("segments");
        let receipts_dir = self.base_dir.join("receipts");
        std::fs::create_dir_all(&segments_dir).map_err(|e| LedgerError::Io(e.to_string()))?;
        std::fs::create_dir_all(&receipts_dir).map_err(|e| LedgerError::Io(e.to_string()))?;

        // naive single-segment file for M0
        let segment_file = segments_dir.join("000001.ndjson");
        let span_json = serde_json::to_string(span).map_err(|e| LedgerError::Serde(e.to_string()))?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&segment_file)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{}", span_json)
            })
            .map_err(|e| LedgerError::Io(e.to_string()))?;

        // write minimal receipt
        let now = Utc::now().to_rfc3339();
        let receipt = Receipt {
            op: "ledger.append".to_string(),
            span_id: span.id.clone(),
            tenant: span.tenant.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            kid: "2025-10A".to_string(),
            sig: "placeholder".to_string(),
            ts: now,
        };
        let receipt_file = receipts_dir.join(format!("{}.ndjson", receipt.jti));
        std::fs::write(&receipt_file, serde_json::to_vec(&receipt).map_err(|e| LedgerError::Serde(e.to_string()))?)
            .map_err(|e| LedgerError::Io(e.to_string()))?;

        Ok(receipt)
    }
}
