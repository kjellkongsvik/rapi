use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, Validation};
use jsonwebtoken::{jwk, jwk::AlgorithmParameters, DecodingKey};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

type Keys = HashMap<String, DecodingKey>;

lazy_static! {
    static ref KEYS: std::sync::RwLock<Keys> = std::sync::RwLock::new(Keys::default());
}

pub async fn init(uri: &str) -> Result<(), AuthError> {
    update_jwks(uri).await?;
    Ok(())
}

async fn update_jwks(uri: &str) -> Result<(), AuthError> {
    let new_keys = decoding_keys(uri).await;
    let mut keys = KEYS.write().map_err(|_| AuthError::InternalServer)?;
    *keys = new_keys;
    Ok(())
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthError::InvalidToken)?;
        let kid = decode_header(bearer.token())
            .map_err(|_| AuthError::InvalidToken)?
            .kid
            .ok_or(AuthError::InvalidToken)?;
        let keys = KEYS.read().map_err(|_| AuthError::InternalServer)?;
        let key = keys.get(&kid).ok_or(AuthError::InvalidToken)?;
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["http://localhost:8080/default"]);
        dbg!(bearer.token());
        let token_data =
            decode::<Claims>(bearer.token(), key, &validation).map_err(|e| {
                tracing::debug!("{:?}", e);
                AuthError::InvalidToken
            })?;

        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::InternalServer => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };
        tracing::debug!("{}, {}", status, error_message);

        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    InternalServer,
}

#[derive(Deserialize)]
struct Oid {
    jwks_uri: String,
}

async fn decoding_keys(uri: &str) -> Keys {
    let jwks_uri = reqwest::get(uri)
        .await
        .expect(&format!("Connection error: {}", &uri))
        .json::<Oid>()
        .await
        .expect(&format!("Value error: {}", &uri))
        .jwks_uri;
    jwks_to_decoding_keys(
        &reqwest::get(&jwks_uri)
            .await
            .expect(&format!("Connection error: {}", &jwks_uri))
            .json()
            .await
            .expect(&format!("Value error: {}", &jwks_uri)),
    )
}

fn jwks_to_decoding_keys(jwks: &jwk::JwkSet) -> HashMap<String, DecodingKey> {
    let mut hm = HashMap::new();
    for jwk in &jwks.keys {
        if let AlgorithmParameters::RSA(ref rsa) = jwk.algorithm {
            if let Ok(decoding_key) = DecodingKey::from_rsa_components(&rsa.n, &rsa.e) {
                if let Some(kid) = jwk.common.key_id.clone() {
                    hm.insert(kid, decoding_key);
                }
            }
        }
    }
    hm
}
