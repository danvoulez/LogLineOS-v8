use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{collections::HashMap, sync::RwLock, time::{Duration as StdDuration, Instant}};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("jwt error: {0}")]
    Jwt(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("oidc error: {0}")]
    Oidc(String),
}

// Replaced by RS256 LLST below

// New strict OIDC code is appended later in this file

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

// ===== Strict Google OIDC with JWKS Cache + LLST RS256 =====
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleIdClaims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

fn aud_matches(expected: &str, aud: &serde_json::Value) -> bool {
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<StdDuration> {
    use reqwest::header::CACHE_CONTROL;
    if let Some(val) = headers.get(CACHE_CONTROL) {
        if let Ok(s) = val.to_str() {
            for part in s.split(',') {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix("max-age=") {
                    if let Ok(secs) = rest.parse::<u64>() {
                        return Some(StdDuration::from_secs(secs));
                    }
                }
            }
        }
    }
    None
}

#[derive(Clone)]
struct CachedJwk { kid: String, key: DecodingKey }

#[derive(Clone)]
struct JwksCache { keys_by_kid: HashMap<String, CachedJwk>, expires_at: Instant }

static JWKS_CACHE: Lazy<RwLock<Option<JwksCache>>> = Lazy::new(|| RwLock::new(None));

async fn fetch_google_jwks() -> Result<(HashMap<String, CachedJwk>, StdDuration), IdentityError> {
    let disc_url = "https://accounts.google.com/.well-known/openid-configuration";
    let client = reqwest::Client::builder()
        .connect_timeout(StdDuration::from_secs(2))
        .timeout(StdDuration::from_secs(5))
        .build()
        .map_err(|e| IdentityError::Http(e.to_string()))?;
    #[derive(Deserialize)]
    struct Disc { jwks_uri: String }
    let disc: Disc = client.get(disc_url)
        .send().await.map_err(|e| IdentityError::Http(e.to_string()))?
        .error_for_status().map_err(|e| IdentityError::Http(e.to_string()))?
        .json().await.map_err(|e| IdentityError::Http(e.to_string()))?;
    let resp = client.get(&disc.jwks_uri)
        .send().await.map_err(|e| IdentityError::Http(e.to_string()))?
        .error_for_status().map_err(|e| IdentityError::Http(e.to_string()))?;
    let headers = resp.headers().clone();
    #[derive(Deserialize)]
    struct JwkSet { keys: Vec<serde_json::Value> }
    let jwks: JwkSet = resp.json().await.map_err(|e| IdentityError::Http(e.to_string()))?;
    let mut map = HashMap::new();
    for k in jwks.keys {
        let kid = k.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let kty = k.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        let alg = k.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if kty != "RSA" || alg != "RS256" || kid.is_empty() { continue; }
        let n = k.get("n").and_then(|v| v.as_str()).ok_or_else(|| IdentityError::Oidc("missing n".into()))?;
        let e = k.get("e").and_then(|v| v.as_str()).ok_or_else(|| IdentityError::Oidc("missing e".into()))?;
        let key = DecodingKey::from_rsa_components(n, e).map_err(|e| IdentityError::Jwt(e.to_string()))?;
        map.insert(kid.clone(), CachedJwk { kid, key });
    }
    let ttl = parse_max_age(&headers).unwrap_or_else(|| StdDuration::from_secs(12*60*60));
    Ok((map, ttl))
}

fn get_cached_key(kid: &str) -> Option<DecodingKey> {
    let cache = JWKS_CACHE.read().ok().and_then(|c| c.clone());
    if let Some(c) = cache { if Instant::now() < c.expires_at { return c.keys_by_kid.get(kid).map(|k| k.key.clone()); }}
    None
}

async fn refresh_and_get_key(kid: &str) -> Result<DecodingKey, IdentityError> {
    let (map, ttl) = fetch_google_jwks().await?;
    {
        let mut guard = JWKS_CACHE.write().map_err(|_| IdentityError::Http("jwks cache".into()))?;
        *guard = Some(JwksCache { keys_by_kid: map.clone(), expires_at: Instant::now() + ttl });
    }
    let guard = JWKS_CACHE.read().map_err(|_| IdentityError::Http("jwks cache".into()))?;
    let c = guard.as_ref().ok_or_else(|| IdentityError::Oidc("jwks empty".into()))?;
    let found = c.keys_by_kid.get(kid).ok_or_else(|| IdentityError::Oidc("kid not found after refresh".into()))?;
    Ok(found.key.clone())
}

pub async fn validate_google_id_token_strict(
    id_token: &str,
    expected_aud: &str,
    expected_iss: &str,
    nonce_if_any: Option<&str>,
) -> Result<GoogleIdClaims, IdentityError> {
    let header = decode_header(id_token).map_err(|e| IdentityError::Jwt(e.to_string()))?;
    if header.alg != Algorithm::RS256 { return Err(IdentityError::Oidc("alg must be RS256".into())); }
    let kid = header.kid.ok_or_else(|| IdentityError::Oidc("missing kid".into()))?;
    let key = if let Some(k) = get_cached_key(&kid) { k } else { refresh_and_get_key(&kid).await? };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.leeway = 60;
    let data = decode::<GoogleIdClaims>(id_token, &key, &validation).map_err(|e| IdentityError::Jwt(e.to_string()))?;
    let claims = data.claims;
    if !(claims.iss == expected_iss || claims.iss == "https://accounts.google.com" || claims.iss == "accounts.google.com") {
        return Err(IdentityError::Oidc("iss mismatch".into()));
    }
    if !aud_matches(expected_aud, &claims.aud) { return Err(IdentityError::Oidc("aud mismatch".into())); }
    if let Some(nonce) = nonce_if_any { if claims.nonce.as_deref() != Some(nonce) { return Err(IdentityError::Oidc("nonce mismatch".into())); } }
    if let Some(nbf) = claims.nbf { if nbf - Utc::now().timestamp() > 60 { return Err(IdentityError::Oidc("nbf too far in future".into())); } }
    Ok(claims)
}

pub fn map_sub_to_llid(sub: &str) -> String { format!("llid:{}", sub) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlstClaimsRs256 {
    pub iss: String,
    pub sub: String,
    pub tenant: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

fn load_rsa_keys_from_env() -> Result<(EncodingKey, Option<DecodingKey>, String), IdentityError> {
    let kid = std::env::var("LL_JWT_KID_ACTIVE").map_err(|_| IdentityError::Config("LL_JWT_KID_ACTIVE".into()))?;
    let pem_active = std::env::var("LL_JWT_PRIV_PEM_ACTIVE").map_err(|_| IdentityError::Config("LL_JWT_PRIV_PEM_ACTIVE".into()))?;
    let enc = EncodingKey::from_rsa_pem(pem_active.as_bytes()).map_err(|e| IdentityError::Jwt(e.to_string()))?;
    let dec_prev = if let Ok(prev) = std::env::var("LL_JWT_PRIV_PEM_PREV") {
        Some(DecodingKey::from_rsa_pem(prev.as_bytes()).map_err(|e| IdentityError::Jwt(e.to_string()))?)
    } else { None };
    Ok((enc, dec_prev, kid))
}

pub fn issue_llst_rs256(
    llid: &str,
    tenant: &str,
    roles: &[String],
    scopes: &[String],
    ttl_secs: i64,
) -> Result<String, IdentityError> {
    let iat = Utc::now().timestamp();
    let nbf = iat;
    let exp = iat + ttl_secs.min(900);
    let jti = Uuid::new_v4().to_string();
    let claims = LlstClaimsRs256 { iss: "loglineos".into(), sub: llid.to_string(), tenant: tenant.to_string(), roles: roles.to_vec(), scopes: scopes.to_vec(), iat, nbf, exp, jti };
    let (enc_key, _prev, kid) = load_rsa_keys_from_env()?;
    let mut header = Header::new(Algorithm::RS256); header.kid = Some(kid);
    encode(&header, &claims, &enc_key).map_err(|e| IdentityError::Jwt(e.to_string()))
}

pub fn verify_llst_rs256(token: &str) -> Result<LlstClaimsRs256, IdentityError> {
    let header = decode_header(token).map_err(|e| IdentityError::Jwt(e.to_string()))?;
    if header.alg != Algorithm::RS256 { return Err(IdentityError::Jwt("LLST alg must be RS256".into())); }
    let pem_active = std::env::var("LL_JWT_PRIV_PEM_ACTIVE").map_err(|_| IdentityError::Config("LL_JWT_PRIV_PEM_ACTIVE".into()))?;
    let dec_active = DecodingKey::from_rsa_pem(pem_active.as_bytes()).map_err(|e| IdentityError::Jwt(e.to_string()))?;
    let mut validation = Validation::new(Algorithm::RS256); validation.validate_exp = true;
    if let Ok(data) = decode::<LlstClaimsRs256>(token, &dec_active, &validation) { return Ok(data.claims); }
    if let Ok(prev) = std::env::var("LL_JWT_PRIV_PEM_PREV") {
        let dec_prev = DecodingKey::from_rsa_pem(prev.as_bytes()).map_err(|e| IdentityError::Jwt(e.to_string()))?;
        if let Ok(data) = decode::<LlstClaimsRs256>(token, &dec_prev, &validation) { return Ok(data.claims); }
    }
    Err(IdentityError::Jwt("invalid LLST".into()))
}
