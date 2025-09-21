use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    JwtError(String),
    #[error("Database url parsing error")]
    DatabaseParsingError,
    #[error("Database connection error")]
    DatabaseConnectionError,
    #[error("Sqlx error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Bcrypt error: {0}")]
    BcryptError(#[from] bcrypt::BcryptError),
    #[error("HTTP request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("You're not authorized!")]
    Unauthorized,
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
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing authorization token")]
    MissingAuthorizationToken,
    #[error("Invalid authorization token")]
    InvalidAuthorizationToken,
    #[error("Json validation error")]
    JsonValidationError,
    #[error("Pkce code verifier not found error")]
    PkceCodeVerifierNotFoundError,
    #[error("Validation error, {0}")]
    ValidationError(#[from] validator::ValidationError),
    #[error("Validation errors, {0}")]
    ValidationErrors(#[from] validator::ValidationErrors),
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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::JwtError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            Self::DatabaseParsingError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database url parsing error".to_string(),
            ),
            Self::DatabaseConnectionError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection error".to_string(),
            ),
            Self::SqlxError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::RedisError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::BcryptError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Request(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized!".to_string()),
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
            AppError::InvalidToken => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid token".to_string(),
            ),
            Self::MissingAuthorizationToken => (
                StatusCode::UNAUTHORIZED,
                "Missing authorization token".to_string(),
            ),
            Self::InvalidAuthorizationToken => (
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
            Self::ValidationError(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::ValidationErrors(e) => (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            Self::RequestTokenError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::NotFoundError { table, value } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{table} not found with this {value}"),
            ),
        };

        let body = Json(json!({"error": error_message}));

        (status, body).into_response()
    }
}
