use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use uuid::Uuid;

#[derive(Type, Deserialize, Serialize, PartialEq, Eq, Default, Debug)]
#[sqlx(type_name = "apartment_condition", rename_all = "lowercase")]
#[sqlx(default)]
pub enum ApartmentCondition {
    #[default]
    New,
    Repaired,
    Old,
}

#[derive(Type, Deserialize, Serialize, PartialEq, Eq, Default, Debug)]
#[sqlx(type_name = "sale_type", rename_all = "lowercase")]
#[sqlx(default)]
pub enum SaleType {
    #[default]
    Buy,
    Rent,
}

#[derive(FromRow, Deserialize, Serialize, PartialEq, Default, Debug)]
#[sqlx(default)]
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

#[derive(FromRow, Deserialize, Serialize, PartialEq, Default, Debug)]
#[sqlx(default)]
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

#[derive(FromRow, Deserialize, Serialize, PartialEq, Default, Debug)]
#[sqlx(default)]
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

#[derive(FromRow, Deserialize, Serialize, PartialEq, Eq, Default, Debug)]
#[sqlx(default)]
pub struct Favorite {
    pub id: Uuid,
    pub user_id: Uuid,
    pub listing_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
