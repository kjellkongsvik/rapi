use std::{env, net::SocketAddr};
use tokio::signal;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let authserver = env::var("AUTHSERVER").expect("AUTHSERVER env variable");

    axum::Server::bind(&addr)
        .serve(rapi::app(&authserver).await.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
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
