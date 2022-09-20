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

pub async fn init(sec_interval: u64, uri: String) -> Result<(), OpenIDError> {
    update_jwks(&uri).await?;
    if sec_interval > 0 {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(sec_interval)).await;
                match update_jwks(&uri).await {
                    Ok(_) => tracing::debug!("Jwks updated"),
                    Err(e) => tracing::error!("Jwks not updated: {:?}", e),
                };
            }
        });
    }
    Ok(())
}

async fn update_jwks(uri: &str) -> Result<(), OpenIDError> {
    let new_keys = decoding_keys(uri).await?;
    let mut keys = KEYS.write().map_err(|_| OpenIDError::InternalServerError)?;
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
        let token_data = decode::<Claims>(
            bearer.token(),
            key,
            &Validation::new(jsonwebtoken::Algorithm::RS256),
        )
        .map_err(|e| {
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

async fn get(uri: &str, retry_every: std::time::Duration) -> reqwest::Response {
    loop {
        match reqwest::get(uri).await {
            Ok(r) => return r,
            _ => {
                tracing::error!("No response: {:?}, retrying in {:?}", uri, retry_every)
            }
        }
        tokio::time::sleep(retry_every).await;
    }
}

async fn decoding_keys(uri: &str) -> Result<Keys, OpenIDError> {
    let jwks_uri = get(uri, std::time::Duration::from_secs(1))
        .await
        .json::<Oid>()
        .await
        .map_err(|_| OpenIDError::MissingOpenIDConfiguration)?
        .jwks_uri;
    Ok(jwks_to_decoding_keys(
        &reqwest::get(&jwks_uri)
            .await
            .map_err(|_| OpenIDError::InvalidJwksUri)?
            .json()
            .await
            .map_err(|_| OpenIDError::MissingJwksSet)?,
    ))
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

#[derive(Debug)]
pub enum OpenIDError {
    InvalidJwksUri,
    MissingOpenIDConfiguration,
    MissingJwksSet,
    InternalServerError,
}
