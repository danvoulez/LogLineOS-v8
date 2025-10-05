use logline_common::Span;
use logline_runtime::{Ledger, FileLedger};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub allow_ledger_append: bool,
}

impl Default for Capabilities {
    fn default() -> Self { Self { allow_ledger_append: true } }
}

#[derive(Debug, Error)]
pub enum HostcallError {
    #[error("capability denied: {0}")]
    Capability(&'static str),
    #[error(transparent)]
    Ledger(#[from] logline_runtime::LedgerError),
}

pub struct Hostcalls {
    caps: Capabilities,
    ledger: FileLedger,
}

impl Hostcalls {
    pub fn new(caps: Capabilities, data_dir: impl Into<std::path::PathBuf>) -> Self {
        Self { caps, ledger: FileLedger::new(data_dir) }
    }

    pub fn ledger_append(&self, span: &Span) -> Result<logline_common::Receipt, HostcallError> {
        if !self.caps.allow_ledger_append { return Err(HostcallError::Capability("ledger.append")); }
        Ok(self.ledger.append(span)?)
    }
}
