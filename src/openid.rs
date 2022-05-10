use axum::{
    async_trait,
    extract::{FromRequest, RequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
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
                    Ok(_) => tracing::debug!("jwks updated"),
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
impl<B> FromRequest<B> for Claims
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| AuthError::InvalidToken)?;
        let kid = decode_header(bearer.token())
            .map_err(|_| AuthError::InvalidToken)?
            .kid
            .ok_or(AuthError::InvalidToken)?;
        let keys = KEYS.read().map_err(|_| AuthError::InternalServer)?;
        let token_data = decode::<Claims>(
            bearer.token(),
            &keys[&kid],
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
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::InternalServer => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };
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

async fn decoding_keys(uri: &str) -> Result<Keys, OpenIDError> {
    let jwks_uri = reqwest::get(uri)
        .await
        .map_err(|_| OpenIDError::InvalidWellKnownUri)?
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
    InvalidWellKnownUri,
    InvalidJwksUri,
    MissingOpenIDConfiguration,
    MissingJwksSet,
    InternalServerError,
}
