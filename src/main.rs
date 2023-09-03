use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    axum::Server::bind(&addr)
        .serve(
            rapi::app(rapi::Config::from_env().await)
                .await
                .into_make_service(),
        )
        .await
        .unwrap();
}
