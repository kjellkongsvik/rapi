use jsonwebtoken::{jwk, jwk::AlgorithmParameters, DecodingKey};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Oid {
    jwks_uri: String,
}

pub fn decoding_keys(uri: &str) -> Result<HashMap<String, DecodingKey>, OpenIDError> {
    let jwks_uri = reqwest::blocking::get(uri)
        .map_err(|_| OpenIDError::InvalidWellKnownUri)?
        .json::<Oid>()
        .map_err(|_| OpenIDError::MissingOpenIDConfiguration)?
        .jwks_uri;
    Ok(jwks_to_decoding_keys(
        &reqwest::blocking::get(&jwks_uri)
            .map_err(|_| OpenIDError::InvalidJwksUri)?
            .json()
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
}
