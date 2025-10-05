use logline_common::Span;
use logline_hostcalls::{Hostcalls, HostcallError};
use logline_validators::validate_canonical;
use thiserror::Error;

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
        Ok(receipt)
    }
}
