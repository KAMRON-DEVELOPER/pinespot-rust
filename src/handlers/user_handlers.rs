use crate::{
    schemas::user_schemas::{LoginSchema, OAuthCallback, UserInfo},
    services::google_oauth::GoogleOAuthClient,
    utilities::{errors::AppError, jwt_with_jsonwebtoken::Claims},
};

use crate::models::user_models::{UserRole, UserStatus};

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{PrivateCookieJar, cookie::Cookie};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse};
use reqwest::Client as ReqwestClient;
use tracing::debug;

use crate::{models::user_models::User, services::database::Database};

pub async fn google_oauth_handler(
    State(client): State<GoogleOAuthClient>,
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, Redirect) {
    // Generate a PKCE challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (authorize_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/calendar".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/plus.me".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    let jar = jar.add(Cookie::new(
        "pkce_verifier",
        pkce_code_verifier.secret().to_string(),
    ));

    (jar, Redirect::to(authorize_url.as_ref()))
}

pub async fn google_oauth_callback_handler(
    State(client): State<GoogleOAuthClient>,
    jar: PrivateCookieJar,
    Query(query): Query<OAuthCallback>,
) -> Result<impl IntoResponse, AppError> {
    let async_http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let pkce_verifier = jar
        .get("pkce_verifier")
        .map(|cookie| oauth2::PkceCodeVerifier::new(cookie.value().to_string()))
        .ok_or(AppError::PkceCodeVerifierNotFoundError)?;

    let token = client
        .exchange_code(AuthorizationCode::new(query.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&async_http_client)
        .await?;

    let oauth_access_token = token.access_token().secret();
    let oauth_refresh_token = token.refresh_token().map(|rt| rt.secret());

    let reqwest_client = ReqwestClient::new();

    let response = reqwest_client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(oauth_access_token.clone())
        .send()
        .await?;

    let profile = response.json::<UserInfo>().await.unwrap();

    println!("oauth_access_token is {:#?}", oauth_access_token);
    println!("oauth_refresh_token is {:#?}", oauth_refresh_token);
    println!("profile is {:#?}", profile);
    debug!("oauth_access_token is {:#?}", oauth_access_token);
    debug!("oauth_refresh_token is {:#?}", oauth_refresh_token);
    debug!("profile is {:#?}", profile);

    Ok(Redirect::to("/"))
}

pub async fn login_handler(
    State(database): State<Database>,
    Json(login_schema): Json<LoginSchema>,
) -> Result<impl IntoResponse, AppError> {
    let user = login_schema.verify(&database).await?.ok_or_else(|| {
        AppError::JwtError("User not found with this username and password".to_string())
    })?;

    Ok(Json(user))
}

pub async fn delete_user(
    State(database): State<Database>,
    claims: Claims,
) -> Result<impl IntoResponse, AppError> {
    println!("claims: {:#?}", claims);

    let query_result = sqlx::query!("DELETE FROM users WHERE id = $1 ", claims.sub)
        .execute(&database.pool)
        .await?;

    match query_result.rows_affected() {
        0 => Err(AppError::NotFoundError {
            table: "User".to_string(),
            value: claims.sub.to_string(),
        }),
        _ => Ok(StatusCode::NO_CONTENT),
    }
}

pub async fn profile_handler(
    State(database): State<Database>,
    claims: Claims,
) -> Result<impl IntoResponse, AppError> {
    let user = sqlx::query_as!(
        User,
        "
        SELECT id, first_name, last_name, email, phone_number, password, avatar_url, role AS \"role: UserRole\", status AS \"status: UserStatus\", created_at, updated_at FROM users WHERE id = $1
        ",
        claims.sub
    )
    .fetch_optional(&database.pool)
    .await?.ok_or_else(|| AppError::NotFoundError {
            table: "User".to_string(),
            value: claims.sub.to_string(),
        })?;

    Ok(Json(user))
}
