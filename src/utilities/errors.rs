use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    JwtError(String),
    #[error("Database url not set error")]
    DatabaseUrlNotSetError,
    #[error("Database url parsing error")]
    DatabaseParsingError,
    #[error("Database connection error")]
    DatabaseConnectionError,
    #[error("Sqlx error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Redis url not set error")]
    RedisUrlNotSetError,
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Bcrypt error: {0}")]
    BcryptError(#[from] bcrypt::BcryptError),
    #[error("Object storage error: {0}")]
    ObjectStorageError(#[from] object_store::Error),
    #[error("HTTP request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("You're not authorized!")]
    UnauthorizedError,
    #[error("Invalid uuid format: {0}")]
    UuidParseError(#[from] uuid::Error),
    #[error("Url parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Openidconnect discovery error: {0}")]
    OpenIdConnectDiscoveryError(
        #[from] openidconnect::DiscoveryError<oauth2::HttpClientError<reqwest::Error>>,
    ),
    #[error("Openidconnect configuration error: {0}")]
    OpenIdConnectConfigurationError(#[from] openidconnect::ConfigurationError),
    #[error("Attempted to get a non-none value but found none")]
    OptionError,
    #[error("Attempted to parse a number to an integer but errored out: {0}")]
    ParseIntError(#[from] std::num::TryFromIntError),
    #[error("Encountered an error trying to convert an infallible value: {0}")]
    FromRequestPartsError(#[from] std::convert::Infallible),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },
    #[error("Wrong credentials")]
    WrongCredentials,
    #[error("Missing credentials")]
    MissingCredentials,
    #[error("Token creation error")]
    TokenCreationError,
    #[error("Invalid token error")]
    InvalidTokenError,
    #[error("Missing authorization token error")]
    MissingAuthorizationTokenError,
    #[error("Missing oauth user id error")]
    MissingOAuthUserIdError,
    #[error("Invalid authorization token error")]
    InvalidAuthorizationTokenError,
    #[error("Missing session token token error")]
    MissingSessionTokenError,
    #[error("Invalid session token error")]
    InvalidSessionTokenError,
    #[error("Session not found error")]
    SessionNotFoundError,
    #[error("Expired session token error")]
    ExpiredSessionTokenError,
    #[error("OAuth user not found error")]
    OAuthUserNotFoundError,
    #[error("OAuth user id expired error")]
    OAuthUserIdExpiredError,
    #[error("Json validation error")]
    JsonValidationError,
    #[error("Pkce code verifier not found error")]
    PkceCodeVerifierNotFoundError,
    #[error("Nonce not found error")]
    NonceNotFoundError,
    #[error("Id token not found error")]
    IdTokenNotFoundError,
    #[error("Openidconnect claims verification error, {0}")]
    OpenIdConnectClaimsVerificationError(#[from] openidconnect::ClaimsVerificationError),
    #[error("Openidconnect signing error, {0}")]
    OpenIdConnectSigningError(#[from] openidconnect::SigningError),
    #[error("Openidconnect signature verification error, {0}")]
    OpenIdConnectSignatureVerificationError(#[from] openidconnect::SignatureVerificationError),
    #[error("Openidconnect http client error, {0}")]
    OpenIdConnectHttpClientError(#[from] openidconnect::HttpClientError<reqwest::Error>),
    #[error("Openidconnect user info error, {0}")]
    OpenIdConnectUserInfoError(
        #[from] openidconnect::UserInfoError<openidconnect::HttpClientError<reqwest::Error>>,
    ),
    #[error("Validation error, {0}")]
    ValidationError(String),
    #[error("Validation error, {0}")]
    ValidatorValidationError(#[from] validator::ValidationError),
    #[error("Validation errors, {0}")]
    ValidatorValidationErrors(#[from] validator::ValidationErrors),
    #[error("Oauth request token error, {0}")]
    RequestTokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),
    #[error("{table} not found with this {value}")]
    NotFoundError { table: String, value: String },
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid ca cert error")]
    InvalidCaCertError(String),
    #[error("Incompatible ca cert type error")]
    IncompatibleCaCertTypeError(String),
    #[error("Invalid client cert error")]
    InvalidClientCertError(String),
    #[error("Incompatible client cert type error")]
    IncompatibleClientCertTypeError(String),
    #[error("Invalid client key error")]
    InvalidClientKeyError(String),
    #[error("Incompatible client key type error")]
    IncompatibleClientKeyTypeError(String),
    #[error("Invalid PEM error")]
    InvalidPemError(#[from] rustls::pki_types::pem::Error),
    #[error("Rustls error")]
    RustlsError(#[from] rustls::Error),
    #[error("Invalid image format error")]
    InvalidImageFormatError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::IoError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::InvalidPemError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::RustlsError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::InvalidCaCertError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid ca cert error, {}", e),
            ),
            Self::IncompatibleCaCertTypeError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(" Incompatible ca cert type error, {}", e),
            ),
            Self::InvalidClientCertError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid client cert error, {}", e),
            ),
            Self::IncompatibleClientCertTypeError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(" Incompatible client cert type error, {}", e),
            ),
            Self::InvalidClientKeyError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid client key error, {}", e),
            ),
            Self::IncompatibleClientKeyTypeError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(" Incompatible client key type error, {}", e),
            ),
            Self::JwtError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            Self::DatabaseUrlNotSetError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database url not set error".to_string(),
            ),
            Self::DatabaseParsingError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database url parsing error".to_string(),
            ),
            Self::DatabaseConnectionError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection error".to_string(),
            ),
            Self::SqlxError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::RedisUrlNotSetError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Redis url not set error".to_string(),
            ),
            Self::RedisError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::BcryptError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::ObjectStorageError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Request(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::UnauthorizedError => (StatusCode::UNAUTHORIZED, "Unauthorized!".to_string()),
            Self::UuidParseError(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Invalid uuid format, {}", e),
            ),
            Self::UrlParseError(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Url parse error, {}", e),
            ),
            Self::OpenIdConnectDiscoveryError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect discovery error, {}", e),
            ),
            Self::OpenIdConnectClaimsVerificationError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect claims verification error, {}", e),
            ),
            Self::OpenIdConnectSigningError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect signing error, {}", e),
            ),
            Self::OpenIdConnectConfigurationError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect configuration error, {}", e),
            ),
            Self::OpenIdConnectSignatureVerificationError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect signature verification error, {}", e),
            ),
            Self::OpenIdConnectHttpClientError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect http client error, {}", e),
            ),
            Self::OpenIdConnectUserInfoError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Openidconnect client info error, {}", e),
            ),
            Self::OptionError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Attempted to get a non-none value but found none".to_string(),
            ),
            Self::ParseIntError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::FromRequestPartsError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::InvalidHeader { expected, found } => (
                StatusCode::BAD_REQUEST,
                format!("invalid header (expected {expected:?}, found {found:?})"),
            ),
            AppError::WrongCredentials => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Wrong credentials".to_string(),
            ),
            AppError::MissingCredentials => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing credentials".to_string(),
            ),
            AppError::TokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Token creation error".to_string(),
            ),
            AppError::InvalidTokenError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid token".to_string(),
            ),
            Self::MissingAuthorizationTokenError => (
                StatusCode::UNAUTHORIZED,
                "Missing authorization token".to_string(),
            ),
            Self::MissingOAuthUserIdError => (
                StatusCode::UNAUTHORIZED,
                "Missing oauth user id error".to_string(),
            ),
            Self::MissingSessionTokenError => (
                StatusCode::UNAUTHORIZED,
                "Missing session token".to_string(),
            ),
            Self::InvalidSessionTokenError => (
                StatusCode::UNAUTHORIZED,
                "Invalid session token".to_string(),
            ),
            Self::SessionNotFoundError => {
                (StatusCode::UNAUTHORIZED, "Session not found".to_string())
            }
            Self::ExpiredSessionTokenError => (
                StatusCode::UNAUTHORIZED,
                "Expired session token".to_string(),
            ),
            Self::OAuthUserNotFoundError => (
                StatusCode::UNAUTHORIZED,
                "OAuth user not found error".to_string(),
            ),
            Self::OAuthUserIdExpiredError => (
                StatusCode::UNAUTHORIZED,
                "OAuth user id expired error".to_string(),
            ),
            Self::InvalidAuthorizationTokenError => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid authorization token".to_string(),
            ),
            Self::JsonValidationError => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Json validation error".to_string(),
            ),
            Self::PkceCodeVerifierNotFoundError => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Pkce code verifier not found error".to_string(),
            ),
            Self::NonceNotFoundError => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Nonce not found error".to_string(),
            ),
            Self::IdTokenNotFoundError => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Id token not found error".to_string(),
            ),
            Self::ValidationError(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::ValidatorValidationError(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::ValidatorValidationErrors(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::RequestTokenError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::NotFoundError { table, value } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{table} not found with this {value}"),
            ),
            Self::InvalidImageFormatError(e) => (StatusCode::UNPROCESSABLE_ENTITY, e),
        };

        let body = Json(json!({"error": error_message}));

        (status, body).into_response()
    }
}
