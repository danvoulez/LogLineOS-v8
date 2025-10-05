use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("jwt error: {0}")]
    Jwt(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("config error: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlstClaims {
    pub sub: String,
    pub tenant: String,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub kid: Option<String>,
}

pub fn issue_llst_hs256(sub: &str, tenant: &str, secret: &str, kid: Option<&str>, ttl_minutes: i64) -> Result<String, IdentityError> {
    let iat = Utc::now();
    let exp = iat + Duration::minutes(ttl_minutes);
    let claims = LlstClaims {
        sub: sub.to_string(),
        tenant: tenant.to_string(),
        roles: None,
        exp: exp.timestamp(),
        iat: iat.timestamp(),
        kid: kid.map(|k| k.to_string()),
    };
    let mut header = Header::new(Algorithm::HS256);
    if let Some(k) = kid { header.kid = Some(k.to_string()); }
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|e| IdentityError::Jwt(e.to_string()))
}

pub fn verify_llst_hs256(token: &str, secret: &str) -> Result<LlstClaims, IdentityError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<LlstClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map(|data| data.claims)
        .map_err(|e| IdentityError::Jwt(e.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<serde_json::Value>,
}

/// Validates a Google id_token by fetching JWKS from the discovery document.
pub async fn validate_google_id_token(id_token: &str, audience: &str) -> Result<serde_json::Value, IdentityError> {
    let disc_url = "https://accounts.google.com/.well-known/openid-configuration";
    let client = reqwest::Client::new();
    let disc: OidcDiscovery = client.get(disc_url).send().await.map_err(|e| IdentityError::Http(e.to_string()))?
        .error_for_status().map_err(|e| IdentityError::Http(e.to_string()))?
        .json().await.map_err(|e| IdentityError::Http(e.to_string()))?;

    let jwks: JwkSet = client.get(&disc.jwks_uri).send().await.map_err(|e| IdentityError::Http(e.to_string()))?
        .error_for_status().map_err(|e| IdentityError::Http(e.to_string()))?
        .json().await.map_err(|e| IdentityError::Http(e.to_string()))?;

    // Use jsonwebtoken's built-in RS decoding by selecting the first RSA key with kid.
    // For brevity, we only attempt RS256 with the first key; production must select by kid.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);

    for key in jwks.keys {
        if let Some(n) = key.get("n").and_then(|v| v.as_str()) {
            if let Some(e) = key.get("e").and_then(|v| v.as_str()) {
                if let Ok(dec_key) = DecodingKey::from_rsa_components(n, e) {
                    if let Ok(data) = decode::<serde_json::Value>(id_token, &dec_key, &validation) {
                        return Ok(data.claims);
                    }
                }
            }
        }
    }

    Err(IdentityError::Jwt("no matching JWK validated the token".into()))
}

pub fn generate_pkce_pair() -> (String, String) {
    let verifier: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    let challenge = {
        let digest = Sha256::digest(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    };
    (verifier, challenge)
}
