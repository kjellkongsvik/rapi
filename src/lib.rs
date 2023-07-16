use axum::{routing::get, Router};
mod auth;

pub async fn app(authserver: &str) -> Router {
    auth::init(authserver)
        .await
        .expect("Init OpenID configuration");

    Router::new()
        .route("/", get(protected))
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "OK"
}

async fn protected(_claims: auth::Claims) -> Result<(), auth::AuthError> {
    Ok(())
}
