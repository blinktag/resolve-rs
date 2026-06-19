use axum::response::IntoResponse;
use axum::{routing::get, Router};
use http::StatusCode;

pub struct Api;

pub fn create_router() -> Router {
    Router::new()
        // `GET /` goes to `root`
        .route("/api/v1/stats", get(stats_handler))
        .route("/health_check", get(health_handler))
}

async fn stats_handler() -> impl IntoResponse {
    (StatusCode::OK, "Hello, world!")
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
