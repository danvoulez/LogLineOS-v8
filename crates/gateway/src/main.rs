use axum::{routing::{get, post}, Router, Json, extract::{State, Query, WebSocketUpgrade}, http::{HeaderMap, HeaderValue, Method, Uri}, body::Bytes, response::IntoResponse};
use axum::extract::ws::{Message, WebSocket};
use std::fs;
use logline_common::{ProblemJson, Span};
use logline_hostcalls::{Capabilities, Hostcalls};
use logline_router::Router as IngestRouter;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use prometheus::{Encoder, IntCounter, TextEncoder, Registry};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use logline_identity::{verify_llst_hs256, issue_llst_hs256, generate_pkce_pair};
use logline_policy::{load_tenant_config, TenantConfig};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::{InMemoryState, NotKeyed}, middleware::NoOpMiddleware};
use std::num::NonZeroU32;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let registry = Registry::new();
    let requests_total = IntCounter::new("gateway_requests_total", "Total HTTP requests").unwrap();
    let append_total = IntCounter::new("ledger_append_total", "Total ledger.append operations").unwrap();
    let derived_edge_total = IntCounter::new("trajectory_edge_total", "Total trajectory_edge events").unwrap();
    let derived_quality_total = IntCounter::new("trajectory_quality_total", "Total trajectory_quality events").unwrap();
    let derived_candidate_total = IntCounter::new("diamond_candidate_total", "Total diamond_candidate events").unwrap();
    registry.register(Box::new(requests_total.clone())).unwrap();
    registry.register(Box::new(append_total.clone())).unwrap();
    registry.register(Box::new(derived_edge_total.clone())).unwrap();
    registry.register(Box::new(derived_quality_total.clone())).unwrap();
    registry.register(Box::new(derived_candidate_total.clone())).unwrap();

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    let tenant_cfg_path = std::env::var("TENANT_CFG").unwrap_or_else(|_| "var/cfg/tenants/example.yaml".into());
    let tenant_cfg = load_tenant_config(&tenant_cfg_path).ok();
    let per_tenant_quota_per_min = std::env::var("TENANT_RPS").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(120);
    let limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware> = RateLimiter::direct(Quota::per_minute(NonZeroU32::new(per_tenant_quota_per_min).unwrap()));
    let app_state = AppState { registry, requests_total, append_total, tenant_cfg, limiter, derived_edge_total, derived_quality_total, derived_candidate_total };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .route("/ingest", post(ingest))
        .route("/auth/llst", post(issue_llst))
        .route("/ingest.ndjson", post(ingest_ndjson))
        .route("/ledger/stream", get(ledger_stream))
        .route("/ws", get(ws_upgrade))
        .route("/oidc/validate", post(oidc_validate))
        .route("/openapi.json", get(openapi))
        .route("/oidc/login", get(oidc_login))
        .route("/oidc/callback", get(oidc_callback))
        .with_state(Arc::new(app_state))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

struct AppState {
    registry: Registry,
    requests_total: IntCounter,
    append_total: IntCounter,
    tenant_cfg: Option<TenantConfig>,
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>,
    derived_edge_total: IntCounter,
    derived_quality_total: IntCounter,
    derived_candidate_total: IntCounter,
}

async fn ingest(State(state): State<Arc<AppState>>, headers: HeaderMap, Json(span): Json<Span>) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ProblemJson>)> {
    state.requests_total.inc();
    // Auth: expect Authorization: Bearer <LLST>
    let llst_secret = std::env::var("LLST_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if verify_llst_hs256(token, &llst_secret).is_err() {
                let problem = ProblemJson::new(401, "invalid or expired token");
                return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem)));
            }
        } else {
            let problem = ProblemJson::new(401, "missing bearer token");
            return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem)));
        }
    } else {
        // Allow bypass in dev only if explicitly enabled
        let allow_dev = std::env::var("ALLOW_DEV_AUTH_BYPASS").ok().map(|v| v == "1").unwrap_or(false);
        if !allow_dev {
            let problem = ProblemJson::new(401, "authorization required");
            return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem)));
        }
    }
    // Simple per-tenant feature gate example (trajectory flag placeholder)
    if let Some(cfg) = &state.tenant_cfg {
        if cfg.tenant != span.tenant {
            let problem = ProblemJson::new(403, "tenant mismatch");
            return Err((axum::http::StatusCode::FORBIDDEN, Json(problem)));
        }
        // trajectory flag would guard derived steps (not yet implemented)
        let _trajectory_enabled = cfg.features.trajectory.unwrap_or(false);
        let _diamond_enabled = cfg.features.diamond.unwrap_or(false);
    }

    // Rate-limit per process (M0 simplified)
    if state.limiter.check().is_err() {
        let problem = ProblemJson::new(429, "rate limit exceeded");
        return Err((axum::http::StatusCode::TOO_MANY_REQUESTS, Json(problem)));
    }
    let host = Hostcalls::new(Capabilities::default(), "var");
    let router = IngestRouter::new(host);
    match router.ingest(&span) {
        Ok(receipt) => {
            state.append_total.inc();
            Ok(Json(serde_json::json!({
            "ok": true,
            "receipt": receipt,
        })))
        }
        Err(err) => {
            let problem = ProblemJson::new(400, format!("ingest error: {}", err));
            Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(problem)))
        }
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> (axum::http::StatusCode, ([(axum::http::header::HeaderName, HeaderValue); 1], Vec<u8>)) {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let mf = state.registry.gather();
    encoder.encode(&mf, &mut buffer).unwrap();
    let headers = [(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4"))];
    (axum::http::StatusCode::OK, (headers, buffer))
}

async fn ingest_ndjson(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ProblemJson>)> {
    state.requests_total.inc();
    // Same auth as /ingest
    let llst_secret = std::env::var("LLST_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if verify_llst_hs256(token, &llst_secret).is_err() {
                let problem = ProblemJson::new(401, "invalid or expired token");
                return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem)));
            }
        } else { let problem = ProblemJson::new(401, "missing bearer token"); return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem))); }
    } else if !std::env::var("ALLOW_DEV_AUTH_BYPASS").ok().map(|v| v == "1").unwrap_or(false) {
        let problem = ProblemJson::new(401, "authorization required");
        return Err((axum::http::StatusCode::UNAUTHORIZED, Json(problem)));
    }

    // Parse NDJSON synchronously for M0
    let text = String::from_utf8(body.to_vec()).map_err(|_| (axum::http::StatusCode::BAD_REQUEST, Json(ProblemJson::new(400, "invalid utf-8"))))?;
    let host = Hostcalls::new(Capabilities::default(), "var");
    let router = IngestRouter::new(host);
    let mut ok = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        match serde_json::from_str::<Span>(line) {
            Ok(span) => match router.ingest(&span) {
                Ok(_) => { ok += 1; },
                Err(e) => errors.push(format!("{}: {}", idx+1, e)),
            }
            Err(e) => errors.push(format!("{}: parse error: {}", idx+1, e)),
        }
    }
    Ok(Json(serde_json::json!({ "ok": true, "ingested": ok, "errors": errors })))
}

#[derive(serde::Deserialize)]
struct OidcLoginParams { redirect_uri: String }

async fn oidc_login(Query(params): Query<OidcLoginParams>) -> impl IntoResponse {
    // Google-only discovery; in production cache discovery
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let (verifier, challenge) = generate_pkce_pair();
    // For M0 demo, return a URL and the verifier so a client can proceed
    let authz_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&client_id), urlencoding::encode(&params.redirect_uri), challenge
    );
    Json(serde_json::json!({ "authz_url": authz_url, "pkce_verifier": verifier }))
}

#[derive(serde::Deserialize)]
struct OidcCallbackParams { code: String, redirect_uri: String, verifier: String }

async fn oidc_callback(Query(_params): Query<OidcCallbackParams>) -> impl IntoResponse {
    // Token exchange omitted in M0; return a stub
    Json(serde_json::json!({ "ok": true, "note": "Token exchange not implemented in M0" }))
}

async fn ledger_stream() -> impl IntoResponse {
    match fs::read("var/ledger/segments/000001.ndjson") {
        Ok(bytes) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"))],
            bytes,
        ),
        Err(_) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"))],
            Vec::new(),
        ),
    }
}

async fn ws_upgrade(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    let _ = socket
        .send(Message::Text("welcome to receipts bus (M0 stub)".into()))
        .await;
}

#[derive(serde::Deserialize)]
struct OidcValidateRequest { id_token: String, audience: String }

async fn oidc_validate(Json(req): Json<OidcValidateRequest>) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ProblemJson>)> {
    match logline_identity::validate_google_id_token(&req.id_token, &req.audience).await {
        Ok(claims) => Ok(Json(serde_json::json!({ "ok": true, "claims": claims }))),
        Err(e) => Err((axum::http::StatusCode::UNAUTHORIZED, Json(ProblemJson::new(401, format!("invalid id_token: {}", e))))),
    }
}

async fn openapi() -> impl IntoResponse {
    let doc = serde_json::json!({
        "openapi": "3.0.0",
        "info": { "title": "LogLineOS v8 API (M0)", "version": "0.1.0" },
        "paths": {
            "/healthz": {"get": {"responses": {"200": {}}}},
            "/metrics": {"get": {"responses": {"200": {}}}},
            "/ingest": {"post": {"requestBody": {"content": {"application/json": {}}}, "responses": {"200": {}}}},
            "/ingest.ndjson": {"post": {"requestBody": {"content": {"application/x-ndjson": {}}}, "responses": {"200": {}}}},
            "/ledger/stream": {"get": {"responses": {"200": {"content": {"application/x-ndjson": {}}}}}},
            "/auth/llst": {"post": {"requestBody": {"content": {"application/json": {}}}, "responses": {"200": {}}}},
            "/oidc/login": {"get": {"parameters": [{"name": "redirect_uri", "in": "query"}], "responses": {"200": {}}}},
            "/oidc/callback": {"get": {"responses": {"200": {}}}},
            "/oidc/validate": {"post": {"requestBody": {"content": {"application/json": {}}}, "responses": {"200": {}}}},
            "/ws": {"get": {"responses": {"101": {}}}}
        }
    });
    (axum::http::StatusCode::OK, Json(doc))
}

#[derive(serde::Deserialize)]
struct IssueLlstRequest { sub: String, tenant: String, #[serde(default)] kid: Option<String>, #[serde(default)] ttl_minutes: Option<i64> }

async fn issue_llst(Json(req): Json<IssueLlstRequest>) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ProblemJson>)> {
    let secret = std::env::var("LLST_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
    let ttl = req.ttl_minutes.unwrap_or(15);
    match issue_llst_hs256(&req.sub, &req.tenant, &secret, req.kid.as_deref(), ttl) {
        Ok(token) => Ok(Json(serde_json::json!({ "llst": token }))),
        Err(e) => {
            let problem = ProblemJson::new(500, format!("could not issue llst: {}", e));
            Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(problem)))
        }
    }
}
