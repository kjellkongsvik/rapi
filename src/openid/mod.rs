use axum::{
    async_trait,
    extract::{FromRequest, RequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections, env};

mod jwks;

static KEYS: Lazy<collections::HashMap<String, DecodingKey>> = Lazy::new(|| {
    let uri = env::var("AUTHSERVER").expect("AUTHSERVER env variable");
    jwks::decoding_keys(&uri).expect("Got DecodingKeys")
});

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
        let token_data = decode::<Claims>(
            bearer.token(),
            &KEYS[&kid],
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
}
