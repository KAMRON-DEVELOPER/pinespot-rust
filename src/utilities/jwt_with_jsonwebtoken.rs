use std::convert::Infallible;

use crate::utilities::errors::AppError;
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utilities::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_token(config: Config, user_id: Uuid, for_refresh: bool) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = if for_refresh {
        now + Duration::days(config.refresh_token_expire_in_days.unwrap() as i64)
    } else {
        now + Duration::minutes(config.access_token_expire_in_minute.unwrap() as i64)
    };
    let claims = Claims {
        sub: user_id,
        iat: now.timestamp() as usize,
        exp: exp.timestamp() as usize,
    };
    let encoding_key = EncodingKey::from_secret(config.secret_key.as_ref().unwrap().as_bytes());
    let encoded_token = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
        .map_err(|_| AppError::TokenCreationError)?;
    Ok(encoded_token)
}

pub fn verify_token(config: Config, token: &str) -> Result<Claims, anyhow::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret_key.as_ref().unwrap().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::InvalidAuthorizationToken)?;
    Ok(token_data.claims)
}

impl<S> FromRequestParts<S> for Claims
where
    Config: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::MissingAuthorizationToken)?;
        let config = Config::from_ref(state);
        let decoding_key = DecodingKey::from_secret(config.secret_key.as_ref().unwrap().as_bytes());
        let token_data = decode::<Claims>(bearer.token(), &decoding_key, &Validation::default())
            .map_err(|_| AppError::InvalidAuthorizationToken)?;
        Ok(token_data.claims)
    }
}

#[derive(Debug)]
pub struct OptionalClaims(pub Option<Claims>);

impl<S> FromRequestParts<S> for OptionalClaims
where
    Config: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Ok(TypedHeader(Authorization(bearer))) =
            parts.extract::<TypedHeader<Authorization<Bearer>>>().await
        else {
            return Ok(OptionalClaims(None));
        };
        let config = Config::from_ref(state);
        let decoding_key = DecodingKey::from_secret(config.secret_key.as_ref().unwrap().as_bytes());
        let token_data = decode::<Claims>(bearer.token(), &decoding_key, &Validation::default());
        Ok(OptionalClaims(
            token_data.ok().map(|token_data| token_data.claims),
        ))
    }
}
