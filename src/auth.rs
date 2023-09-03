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
use std::{collections::HashMap, str::FromStr};

type Keys = HashMap<String, Jwk>;

lazy_static! {
    static ref KEYS: std::sync::RwLock<Keys> = std::sync::RwLock::new(Keys::default());
}

pub async fn init(uri: &str, audience: &str) -> Result<(), AuthError> {
    update_jwks(uri, audience).await?;
    Ok(())
}

async fn update_jwks(uri: &str, audience: &str) -> Result<(), AuthError> {
    let new_keys = decoding_keys(uri, audience).await;
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
                .map_err(|_| AuthError::Unauthorized)?;
        let kid = decode_header(bearer.token())
            .map_err(|_| AuthError::Unauthorized)?
            .kid
            .ok_or(AuthError::Unauthorized)?;
        let keys = KEYS.read().map_err(|_| AuthError::InternalServer)?;
        let key = keys.get(&kid).ok_or(AuthError::Unauthorized)?;
        let token_data =
            decode::<Claims>(bearer.token(), &key.decoding, &key.validation).map_err(
                |e| {
                    dbg!(e);
                    AuthError::Unauthorized
                },
            )?;

        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
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
    Unauthorized,
    InternalServer,
}

#[derive(Deserialize)]
struct Oid {
    jwks_uri: String,
    issuer: String,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

#[derive(Clone)]
struct Jwk {
    decoding: DecodingKey,
    validation: Validation,
}

async fn decoding_keys(uri: &str, audience: &str) -> Keys {
    let oid = reqwest::get(uri)
        .await
        .expect(&format!("Connection error: {}", &uri))
        .json::<Oid>()
        .await
        .expect(&format!("Value error: {}", &uri));
    let jwks = reqwest::get(&oid.jwks_uri)
        .await
        .expect(&format!("Connection error"))
        .json()
        .await
        .expect(&format!("Value error"));
    let alg = match &oid.id_token_signing_alg_values_supported {
        Some(algs) => match algs.first() {
            Some(s) => Some(jsonwebtoken::Algorithm::from_str(s).unwrap()),
            _ => None,
        },
        _ => None,
    };

    jwks_to_decoding_keys(&jwks, audience, &oid.issuer, alg)
}

fn jwks_to_decoding_keys(
    jwks: &jwk::JwkSet,
    audience: &str,
    issuer: &str,
    alg: Option<jsonwebtoken::Algorithm>,
) -> HashMap<String, Jwk> {
    let mut hm = HashMap::new();
    for jwk in &jwks.keys {
        if let AlgorithmParameters::RSA(ref rsa) = jwk.algorithm {
            if let Ok(decoding) = DecodingKey::from_rsa_components(&rsa.n, &rsa.e) {
                if let Some(ref kid) = jwk.common.key_id {
                    let mut validation =
                        Validation::new(jwk.common.algorithm.or(alg).unwrap());
                    validation.set_issuer(&[issuer]);
                    validation.set_audience(&[audience]);
                    hm.insert(
                        kid.into(),
                        Jwk {
                            decoding,
                            validation,
                        },
                    );
                }
            }
        }
    }
    hm
}
