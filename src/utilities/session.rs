use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{Database, utilities::errors::AppError};

use serde::{Deserialize, Serialize};

#[derive(FromRow, Deserialize, Serialize, Default, Debug)]
#[sqlx(default)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl<S> FromRequestParts<S> for Session
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await?;
        let cookie = jar
            .get("session")
            .ok_or(AppError::MissingSessionTokenError)?;
        let session_token = cookie.value();

        let db = Database::from_ref(state);
        let session = sqlx::query_as!(
            Session,
            r#"
                SELECT * FROM sessions
                WHERE session_token = $1
            "#,
            session_token
        )
        .fetch_optional(&db.pool)
        .await?
        .ok_or(AppError::SessionNotFoundError)?;

        if session.expires_at < Utc::now() {
            return Err(AppError::ExpiredSessionTokenError);
        }

        Ok(session)
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct OauthUserId(pub Uuid);

impl<S> FromRequestParts<S> for OauthUserId
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await?;
        if let Some(cookie) = jar.get("oauth_user_id") {
            let oauth_user_id = Uuid::parse_str(cookie.value())?;
            return Ok(Self(oauth_user_id));
        }
        Err(AppError::MissingOAuthUserIdError)
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct OptionalOauthUserId(pub Option<Uuid>);

impl<S> FromRequestParts<S> for OptionalOauthUserId
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state).await?;
        if let Some(cookie) = jar.get("oauth_user_id") {
            let oauth_user_id = Uuid::parse_str(cookie.value())?;
            return Ok(Self(Some(oauth_user_id)));
        }

        Ok(Self(None))
    }
}
