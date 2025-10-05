use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LllbManifest {
    pub name: String,
    pub version: String,
    pub abi: String,
    #[serde(default)]
    pub caps_allow: Vec<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub resources: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("abi not supported: {0}")]
    Abi(String),
}

pub fn load_lllb(path: impl AsRef<std::path::Path>) -> Result<LllbManifest, LoaderError> {
    let bytes = std::fs::read(path).map_err(|e| LoaderError::Io(e.to_string()))?;
    let m: LllbManifest = serde_json::from_slice(&bytes).map_err(|e| LoaderError::Parse(e.to_string()))?;
    if m.abi != "v1" { return Err(LoaderError::Abi(m.abi)); }
    Ok(m)
}
