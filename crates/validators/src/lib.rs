use logline_common::{Span, SpanStatus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("invalid field: {0}")]
    Invalid(&'static str),
}

pub fn validate_canonical(span: &Span) -> Result<(), ValidationError> {
    if span.id.trim().is_empty() { return Err(ValidationError::Missing("id")); }
    if span.tenant.trim().is_empty() { return Err(ValidationError::Missing("tenant")); }
    if span.who.trim().is_empty() { return Err(ValidationError::Missing("who")); }
    if span.did.trim().is_empty() { return Err(ValidationError::Missing("did")); }
    if span.this.trim().is_empty() { return Err(ValidationError::Missing("this")); }
    if span.when.trim().is_empty() { return Err(ValidationError::Missing("when")); }
    match span.status { SpanStatus::Confirmed | SpanStatus::Proposed | SpanStatus::Rejected => {} }
    Ok(())
}
