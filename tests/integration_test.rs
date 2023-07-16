use axum::{body::Body, http, http::Request};
use reqwest::{self, StatusCode};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Token {
    access_token: String,
}

const WELL_KNOWN: &'static str = ".well-known/openid-configuration";
const OID_SERVER: &'static str = "http://localhost:8080/default";

async fn token(uri: &str) -> Token {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", "id"),
        ("client_secret", "secret"),
        ("code", "any_code"),
        ("redirect_uri", "anywhere"),
    ];
    let client = reqwest::Client::new();
    let res = Box::new(client.post(uri).form(&params))
        .send()
        .await
        .expect("Connection to openid server");
    serde_json::from_str(&res.text().await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore]
async fn requires_token_ok() {
    let token = token(&format!("{OID_SERVER}/token")).await.access_token;
    let resp = rapi::app(&format!("{OID_SERVER}/{WELL_KNOWN}"))
        .await
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/")
                .header("Authorization", "Bearer ".to_owned() + &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn requires_token() {
    let resp = rapi::app(&format!("{OID_SERVER}/{WELL_KNOWN}"))
        .await
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
