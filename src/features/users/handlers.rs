use crate::{
    features::users::schemas::CompleteProfileSchema,
    services::google_oauth::GoogleOAuthClient,
    utilities::{
        errors::AppError,
        generate_session_token::generate_session_token,
        session::{OauthUserId, OptionalOauthUserId, Session},
    },
};
use bcrypt::{DEFAULT_COST, hash};
use std::net::SocketAddr;

use object_store::path::Path as ObjectStorePath;

use cookie::{
    SameSite,
    time::{Duration as CookieDuration, OffsetDateTime},
};

use axum::{
    Json,
    extract::{ConnectInfo, Multipart, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::{
    TypedHeader,
    extract::{PrivateCookieJar, cookie::Cookie},
    headers::UserAgent,
};
use chrono::{Duration, Utc};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};

use object_store::{ObjectStore, gcp::GoogleCloudStorage};
use reqwest::Client;
use tracing::debug;
use uuid::Uuid;

use crate::{
    features::users::{
        models::{OAuthUser, User, UserRole, UserStatus},
        schemas::{LoginSchema, OAuthCallback, PhoneResponse},
    },
    services::database::Database,
};

pub async fn google_oauth_handler(
    jar: PrivateCookieJar,
    OptionalOauthUserId(optional_oauth_user_id): OptionalOauthUserId,
    State(database): State<Database>,
    State(oauth_client): State<GoogleOAuthClient>,
) -> Result<(PrivateCookieJar, Redirect), AppError> {
    if let Some(oauth_user_id) = optional_oauth_user_id {
        if let Some(exp) = sqlx::query_scalar!(
            r#"SELECT exp FROM oauth_users WHERE id = $1"#,
            oauth_user_id
        )
        .fetch_optional(&database.pool)
        .await?
            && exp <= Utc::now()
        {
            sqlx::query_scalar!(r#"DELETE FROM oauth_users WHERE id = $1"#, oauth_user_id)
                .execute(&database.pool)
                .await?;
        }

        return Ok((jar, Redirect::to("/complete-profile")));
    }

    // No cookie, start OAuth flow
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, _csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/user.phonenumbers.read".to_string(),
        ))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    let mut pkce_verifier_cookie =
        Cookie::new("pkce_verifier", pkce_code_verifier.secret().to_string());
    pkce_verifier_cookie.set_http_only(true);
    pkce_verifier_cookie.set_same_site(SameSite::None);
    pkce_verifier_cookie.set_secure(false);
    let jar = jar.add(pkce_verifier_cookie);

    Ok((jar, Redirect::to(auth_url.as_ref())))
}

pub async fn google_oauth_callback_handler(
    jar: PrivateCookieJar,
    State(http_client): State<Client>,
    State(database): State<Database>,
    Query(query): Query<OAuthCallback>,
    State(oauth_client): State<GoogleOAuthClient>,
) -> Result<(PrivateCookieJar, Redirect), AppError> {
    let pkce_verifier = jar
        .get("pkce_verifier")
        .map(|cookie| PkceCodeVerifier::new(cookie.value().to_string()))
        .ok_or(AppError::PkceCodeVerifierNotFoundError)?;

    let token_response = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .set_pkce_verifier(pkce_verifier)
        .add_extra_param("name", "value")
        .request_async(&http_client)
        .await?;

    let oauth_access_token = token_response.access_token().secret();
    let _oauth_refresh_token = token_response.refresh_token().map(|rt| rt.secret());

    let oauth_user_response = http_client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(oauth_access_token.clone())
        .send()
        .await?;
    let oauth_user = oauth_user_response.json::<OAuthUser>().await?;
    debug!("oauth user: {:?}", oauth_user);

    let phone_number_response = http_client
        .get("https://people.googleapis.com/v1/people/me?personFields=phoneNumbers")
        .bearer_auth(oauth_access_token.clone())
        .send()
        .await?;
    let phone_number = phone_number_response.json::<PhoneResponse>().await?;
    debug!("phone number: {:?}", phone_number);

    let phone_number = phone_number
        .phone_numbers
        .as_ref()
        .and_then(|v| v.first())
        .map(|p| &p.value);

    let oauth_user_id = sqlx::query_scalar!(
        r#"
            INSERT INTO oauth_users (exp, iat, iss, sub, at_hash, email, family_name, given_name, name, picture, phone_number)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
        "#,
        oauth_user.exp,
        oauth_user.iat,
        oauth_user.iss,
        oauth_user.sub,
        oauth_user.at_hash,
        oauth_user.email,
        oauth_user.family_name,
        oauth_user.given_name,
        oauth_user.name,
        oauth_user.picture,
        phone_number
    )
    .fetch_one(&database.pool)
    .await?;

    let exp_chrono = oauth_user.exp;
    let exp_offset = OffsetDateTime::from_unix_timestamp(exp_chrono.timestamp()).unwrap();

    let mut oauth_user_id_cookie = Cookie::new("oauth_user_id", oauth_user_id.to_string());
    oauth_user_id_cookie.set_http_only(true);
    oauth_user_id_cookie.set_same_site(SameSite::None);
    oauth_user_id_cookie.set_secure(false);
    oauth_user_id_cookie.set_expires(exp_offset);
    let jar = jar.add(oauth_user_id_cookie);

    Ok((jar, Redirect::to("/complete-profile")))
}

pub async fn get_oauth_user(
    OauthUserId(oauth_user_id): OauthUserId,
    State(database): State<Database>,
) -> Result<impl IntoResponse, AppError> {
    let oauth_user = sqlx::query_as!(
        OAuthUser,
        r#"
            SELECT * FROM oauth_users WHERE id = $1 AND exp > NOW()
        "#,
        oauth_user_id
    )
    .fetch_optional(&database.pool)
    .await?
    .ok_or(AppError::OAuthUserNotFoundError)?;

    if oauth_user.exp <= Utc::now() {
        sqlx::query_scalar!(r#"DELETE FROM oauth_users WHERE id = $1"#, oauth_user_id)
            .execute(&database.pool)
            .await?;
        return Err(AppError::OAuthUserIdExpiredError);
    }

    Ok(Json(oauth_user))
}

pub async fn complete_profile_handler(
    jar: PrivateCookieJar,
    OauthUserId(oauth_user_id): OauthUserId,
    State(gcs): State<GoogleCloudStorage>,
    // State(s3): State<AmazonS3>,
    State(database): State<Database>,
    TypedHeader(user_agent): TypedHeader<UserAgent>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> Result<(PrivateCookieJar, impl IntoResponse), AppError> {
    // let pending_cookie = jar.get("pending_id").ok_or(AppError::UnauthorizedError)?;
    // let pending_id = Uuid::parse_str(pending_cookie.value())?;

    let oauth_user = sqlx::query_as!(
        OAuthUser,
        r#"
            SELECT * FROM oauth_users WHERE id = $1 AND exp > NOW()
        "#,
        oauth_user_id
    )
    .fetch_optional(&database.pool)
    .await?
    .ok_or(AppError::OAuthUserNotFoundError)?;

    if oauth_user.exp <= Utc::now() {
        sqlx::query_scalar!(r#"DELETE FROM oauth_users WHERE id = $1"#, oauth_user_id)
            .execute(&database.pool)
            .await?;
        return Err(AppError::OAuthUserIdExpiredError);
    }

    let mut complete_profile_schema = CompleteProfileSchema {
        given_name: None,
        family_name: None,
        email: None,
        password: None,
        phone_number: None,
        picture: None,
    };

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();

        match name.as_str() {
            "given_name" => {
                complete_profile_schema.given_name = Some(field.text().await.unwrap());
            }
            "family_name" => {
                complete_profile_schema.family_name = Some(field.text().await.unwrap());
            }
            "email" => {
                complete_profile_schema.email = Some(field.text().await.unwrap());
            }
            "password" => {
                complete_profile_schema.password = Some(field.text().await.unwrap());
            }
            "phone_number" => {
                complete_profile_schema.phone_number = Some(field.text().await.unwrap());
            }
            "picture" => {
                let data = field.bytes().await.unwrap();
                let pic_id = Uuid::new_v4();
                let ext = infer::get(&data)
                    .ok_or_else(|| {
                        AppError::InvalidImageFormatError("Invalid image format".to_string())
                    })?
                    .extension();
                let location =
                    ObjectStorePath::from(format!("{}/{}.{}", oauth_user_id, pic_id, ext));
                gcs.put(&location, data.into()).await?;
                complete_profile_schema.picture = Some(location);
            }
            _ => {}
        }
    }

    debug!("complete_profile_schema: {:#?}", complete_profile_schema);

    let picture = complete_profile_schema.picture.map(|p| p.to_string());
    let hash_password = hash(complete_profile_schema.password.unwrap(), DEFAULT_COST)?;

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (first_name, last_name, email, phone_number, password, picture)
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING
            id,
            first_name,
            last_name,
            email,
            phone_number,
            password,
            picture,
            role AS "role: UserRole",
            status AS "status: UserStatus",
            created_at,
            updated_at
        "#,
        complete_profile_schema.given_name.unwrap(),
        complete_profile_schema.family_name.unwrap(),
        complete_profile_schema.email.unwrap(),
        complete_profile_schema.phone_number,
        hash_password,
        picture
    )
    .fetch_one(&database.pool)
    .await?;

    let session_token = generate_session_token();
    let expires_at = Utc::now() + Duration::days(1);
    let user_agent = user_agent.to_string();
    let ip_address = addr.ip().to_string();

    sqlx::query!(
        r#"
        INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at)
        VALUES ($1,$2,$3,$4,$5)
        "#,
        user.id,
        session_token,
        ip_address,
        user_agent,
        expires_at
    )
    .execute(&database.pool)
    .await?;

    let mut session_token_cookie = Cookie::new("session_token", session_token.to_string());
    session_token_cookie.set_http_only(true);
    session_token_cookie.set_same_site(SameSite::None);
    session_token_cookie.set_secure(false);
    session_token_cookie.set_max_age(Some(CookieDuration::weeks(52)));

    let jar = jar.add(session_token_cookie);
    let jar = jar.remove(Cookie::from("oauth_user_id"));
    let jar = jar.remove(Cookie::from("pkce_verifier"));

    Ok((jar, Json(user)))
}

pub async fn login_handler(
    jar: PrivateCookieJar,
    State(database): State<Database>,
    TypedHeader(user_agent): TypedHeader<UserAgent>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(login_schema): Json<LoginSchema>,
) -> Result<impl IntoResponse, AppError> {
    debug!("login_schema is {:#?}", login_schema);

    let user = login_schema.verify(&database).await?.ok_or_else(|| {
        AppError::NotFoundError("User not found with this username and password".to_string())
    })?;

    let session_token = generate_session_token();
    let expires_at = Utc::now() + Duration::days(1);
    let user_agent = user_agent.to_string();
    let ip_address = addr.ip().to_string();

    sqlx::query!(
        r#"
            DELETE FROM sessions where user_id = $1
        "#,
        user.id
    )
    .execute(&database.pool)
    .await?;

    sqlx::query!(
        r#"
            INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at)
            VALUES ($1,$2,$3,$4,$5)
        "#,
        user.id,
        session_token,
        ip_address,
        user_agent,
        expires_at
    )
    .execute(&database.pool)
    .await?;

    let mut session_token_cookie = Cookie::new("session_token", session_token.to_string());
    session_token_cookie.set_http_only(true);
    session_token_cookie.set_same_site(SameSite::None);
    session_token_cookie.set_secure(false);
    session_token_cookie.set_max_age(Some(CookieDuration::weeks(52)));

    let jar = jar.add(session_token_cookie);

    Ok((jar, Json(user)))
}

pub async fn get_user_handler(
    session: Session,
    State(database): State<Database>,
) -> Result<impl IntoResponse, AppError> {
    debug!("claims: {:#?}", session);

    let user = sqlx::query_as!(
        User,
        r#"
            SELECT
                id,
                first_name,
                last_name,
                email,
                phone_number,
                password,
                picture,
                role AS "role: UserRole",
                status AS "status: UserStatus",
                created_at,
                updated_at
            FROM users WHERE id = $1
        "#,
        session.user_id
    )
    .fetch_optional(&database.pool)
    .await?
    .ok_or_else(|| AppError::NotFoundError("User not found".to_string()))?;

    Ok(Json(user))
}

pub async fn update_user_handler() {}

pub async fn delete_user_handler(
    session: Session,
    State(database): State<Database>,
) -> Result<impl IntoResponse, AppError> {
    debug!("claims: {:#?}", session);

    let query_result = sqlx::query!("DELETE FROM users WHERE id = $1", session.user_id)
        .execute(&database.pool)
        .await?;

    match query_result.rows_affected() {
        0 => Err(AppError::NotFoundError("User not found".to_string())),
        _ => Ok(StatusCode::NO_CONTENT),
    }
}
