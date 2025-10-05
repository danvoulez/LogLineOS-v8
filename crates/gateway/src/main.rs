use axum::{routing::{get, post}, Router, Json};
use logline_common::{ProblemJson, Span};
use logline_runtime::{FileLedger, Ledger};
use logline_validators::validate_canonical;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ingest", post(ingest));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

async fn ingest(Json(span): Json<Span>) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<ProblemJson>)> {
    if let Err(err) = validate_canonical(&span) {
        let problem = ProblemJson::new(400, format!("validation error: {}", err));
        return Err((axum::http::StatusCode::BAD_REQUEST, Json(problem)));
    }

    let ledger = FileLedger::new("var");
    match ledger.append(&span) {
        Ok(receipt) => Ok(Json(serde_json::json!({
            "ok": true,
            "receipt": receipt,
        }))),
        Err(err) => {
            let problem = ProblemJson::new(500, format!("ledger error: {}", err));
            Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(problem)))
        }
    }
}
