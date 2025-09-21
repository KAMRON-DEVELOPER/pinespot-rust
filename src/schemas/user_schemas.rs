use crate::models::user_models::{UserRole, UserStatus};
use crate::utilities::errors::AppError;

use bcrypt::verify;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::user_models::User;
use crate::services::database::Database;

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginSchema {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 32,
        message = "Password should be long beetween 8 and 32"
    ))]
    pub password: String,
}

impl LoginSchema {
    pub async fn verify(self, database: &Database) -> Result<Option<User>, AppError> {
        self.validate()?;

        let maybe_user = sqlx::query_as!(
            User,
            "
            SELECT id, first_name, last_name, email, phone_number, password, avatar_url, role AS \"role: UserRole\", status AS \"status: UserStatus\", created_at, updated_at FROM users WHERE email = $1
            ",
            self.email
        )
        .fetch_optional(&database.pool)
        .await?;

        if let Some(user) = maybe_user {
            let verified = verify(self.password.as_bytes(), &user.password)?;

            if verified {
                return Ok(Some(user));
            }
        }

        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    pub(crate) code: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub photo_url: Option<String>,
}
