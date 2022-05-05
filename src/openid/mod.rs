use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use once_cell::sync::Lazy;
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use serde::{Deserialize, Serialize};
use std::{collections, env};

mod jwks;

static KEYS: Lazy<collections::HashMap<String, DecodingKey>> = Lazy::new(|| {
    let uri = env::var("AUTHSERVER").expect("AUTHSERVER env variable");
    jwks::decoding_keys(&uri).expect("Got DecodingKeys")
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Claims {
    type Error = String;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> request::Outcome<Self, Self::Error> {
        if let Some(b) = request.headers().get_one("Authorization") {
            if let Some(t) = b.strip_prefix("Bearer ") {
                if let Ok(header) = decode_header(t) {
                    if let Some(kid) = header.kid {
                        if let Ok(_c) = decode::<Claims>(
                            t,
                            &KEYS[&kid],
                            &Validation::new(jsonwebtoken::Algorithm::RS256),
                        ) {
                            return Outcome::Success(Claims {});
                        }
                    }
                }
            }
        }

        Outcome::Failure((Status::Unauthorized, "Unauthorized".into()))
    }
}
