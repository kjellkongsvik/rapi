use axum::{routing::get, Router};
use std::{env, net::SocketAddr};
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod openid;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "rapi=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    openid::init(
        std::env::var("JWKS_UPDATE_INTERVAL")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .expect("Number of seconds as interval between updates"),
        env::var("AUTHSERVER").expect("AUTHSERVER env variable"),
    )
    .await
    .expect("Init OpenID configuration");

    let app = Router::new()
        .route("/", get(protected))
        .route("/health", get(health));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn health() -> &'static str {
    "OK"
}

async fn protected(_claims: openid::Claims) -> Result<(), openid::AuthError> {
    Ok(())
}

async fn shutdown_signal() {
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = terminate => {},
    }
}
