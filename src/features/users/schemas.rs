use crate::{
    features::users::models::{User, UserRole, UserStatus},
    utilities::errors::AppError,
};
use bcrypt::verify;
use object_store::path::Path as ObjectStorePath;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::services::database::Database;

#[derive(Deserialize, Serialize, Debug)]
pub struct Token {
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize, Validate, Debug)]
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
                FROM users WHERE email = $1
            "#,
            self.email
        )
        .fetch_optional(&database.pool)
        .await?;

        if let Some(user) = maybe_user {
            let verified = match user.password.as_deref() {
                Some(hash) => verify(&self.password, hash)?,
                None => false,
            };

            if verified {
                return Ok(Some(user));
            }
        }

        Ok(None)
    }
}

#[derive(Deserialize, Debug)]
pub struct OAuthCallback {
    pub(crate) code: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PhoneResponse {
    pub phone_numbers: Option<Vec<PhoneNumber>>,
}

#[derive(Deserialize, Debug)]
pub struct PhoneNumber {
    pub value: String,
}

#[derive(Debug)]
pub struct CompleteProfileSchema {
    pub email: Option<String>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub password: Option<String>,
    pub phone_number: Option<String>,
    pub picture: Option<ObjectStorePath>,
}
