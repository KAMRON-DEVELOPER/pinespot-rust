use jwt_simple::{
    claims::Claims,
    prelude::{Duration, HS256Key, MACLike},
};
use uuid::Uuid;

use crate::utilities::{config::Config, errors::AppError};

pub fn create_token(config: Config, user_id: Uuid, for_refresh: bool) -> Result<String, AppError> {
    let valid_for = if for_refresh {
        Duration::from_days(config.refresh_token_expire_in_days.unwrap() as u64)
    } else {
        Duration::from_mins(config.access_token_expire_in_minute.unwrap() as u64)
    };
    let key = HS256Key::from_bytes(config.secret_key.as_ref().unwrap().as_bytes());
    let claims = Claims::create(valid_for).with_subject(user_id);
    // reaise jwt_simple::Error
    let token = key
        .authenticate(claims)
        .map_err(|_| AppError::TokenCreationError)?;
    Ok(token)
}

pub fn verify_token(config: Config, token: &str) -> Result<Uuid, AppError> {
    let key = HS256Key::from_bytes(config.secret_key.as_ref().unwrap().as_bytes());
    let verified_token = key
        .verify_token::<Uuid>(token, None)
        .map_err(|_| AppError::InvalidAuthorizationTokenError)?;
    Ok(verified_token.custom)
}
