use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Regular,
}

#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disactive,
}

#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[sqlx(type_name = "apartment_condition", rename_all = "lowercase")]
pub enum ApartmentCondition {
    New,
    Repaired,
    Old,
}

#[derive(sqlx::Type, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[sqlx(type_name = "sale_type", rename_all = "lowercase")]
pub enum SaleType {
    Buy,
    Rent,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct User {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone_number: String,
    pub password: String,
    pub avatar_url: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Listing {
    pub id: Uuid,
    pub apartment_id: Uuid,
    pub owner_id: Uuid,
    pub price: f64,
    pub available_from: Option<DateTime<Utc>>,
    pub available_to: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Apartment {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub rooms: Option<i32>,
    pub area: Option<f64>,
    pub floor: Option<i32>,
    pub has_elevator: Option<bool>,
    pub condition: Option<ApartmentCondition>,
    pub sale_type: SaleType,
    pub requirements: Option<String>,
    pub has_garden: Option<bool>,
    pub distance_to_kindergarten: Option<f64>,
    pub distance_to_school: Option<f64>,
    pub distance_to_hospital: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Debug)]
pub struct Address {
    pub id: Uuid,
    pub apartment_id: Uuid,
    pub street_address: String,
    pub city: String,
    pub state_or_region: String,
    pub county_or_district: Option<String>,
    pub postal_code: String,
    pub country: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Favorite {
    pub id: Uuid,
    pub user_id: Uuid,
    pub listing_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
