use std::{env, net::SocketAddr};

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let authserver = env::var("AUTHSERVER").expect("AUTHSERVER env variable");
    let audience = env::var("AUDIENCE").expect("AUDIENCE env variable");

    axum::Server::bind(&addr)
        .serve(rapi::app(&authserver, &audience).await.into_make_service())
        .await
        .unwrap();
}
