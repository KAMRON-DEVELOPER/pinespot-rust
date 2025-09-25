use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use uuid::Uuid;

#[derive(Type, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    #[default]
    Regular,
}

#[derive(Type, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    #[default]
    Active,
    Disactive,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[sqlx(default)]
pub struct User {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone_number: Option<String>,
    #[sqlx(default)]
    pub password: Option<String>,
    pub picture: Option<String>,
    #[sqlx(default)]
    pub role: UserRole,
    #[sqlx(default)]
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[sqlx(default)]
pub struct OAuthUser {
    pub id: Uuid,
    pub exp: DateTime<Utc>,
    pub iat: DateTime<Utc>,
    pub iss: String,
    pub sub: String,
    pub at_hash: Option<String>,
    pub email: Option<String>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
