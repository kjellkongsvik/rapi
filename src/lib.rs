use axum::{routing::get, Router};
mod auth;

pub async fn app(config: auth::Config) -> Router {
    Router::new()
        .route("/", get(protected))
        .route("/health", get(health))
        .with_state(auth::AppState { config })
}

async fn health() -> &'static str {
    "OK"
}

async fn protected(_claims: auth::Claims) -> Result<(), auth::AuthError> {
    Ok(())
}

pub use auth::Config;
