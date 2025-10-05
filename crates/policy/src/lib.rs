use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureFlags {
    pub trajectory: Option<bool>,
    pub diamond: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    pub tenant: String,
    #[serde(default)]
    pub features: FeatureFlags,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

pub fn load_tenant_config(path: impl AsRef<std::path::Path>) -> Result<TenantConfig, ConfigError> {
    let bytes = std::fs::read(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    let cfg: TenantConfig = serde_yaml::from_slice(&bytes).map_err(|e| ConfigError::Parse(e.to_string()))?;
    Ok(cfg)
}
