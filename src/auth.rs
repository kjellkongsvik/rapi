use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use jsonwebtoken::{decode, decode_header, Validation};
use jsonwebtoken::{jwk, jwk::AlgorithmParameters, DecodingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tokio::time::Instant;
type Keys = HashMap<String, Jwk>;

#[derive(Clone)]
pub struct Config {
    oidc_url: String,
    audience: String,
    key_store: KeyStore,
}

#[derive(Clone)]
struct KeyStore {
    when: Instant,
    keys: Keys,
}

impl Config {
    pub fn from_env() -> Self {
        let oidc_url = env::var("AUTHSERVER").expect("AUTHSERVER env variable");
        let audience = env::var("AUDIENCE").expect("AUDIENCE env variable");
        Self {
            oidc_url,
            audience,
            key_store: KeyStore::new(),
        }
    }
}

impl KeyStore {
    fn new() -> Self {
        Self {
            when: Instant::now(),
            keys: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Mutex<Config>>,
}

impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    Config: FromRef<S>,
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
        // if let State<S>(s) = state {};
        let config = Config::from_ref(state);
        let keys = decoding_keys(config.oidc_url, config.audience)
            .await
            .unwrap();
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

async fn decoding_keys(uri: String, audience: String) -> Result<Keys, ()> {
    dbg!(format!("get config from {uri}"));
    let oid = reqwest::get(&uri)
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

    Ok(jwks_to_decoding_keys(&jwks, &audience, &oid.issuer, alg))
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
