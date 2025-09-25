use crate::features::listings::models::Listing;
use serde::Serialize;

#[derive(Serialize)]
pub struct ListingResponse {
    pub listings: Vec<Listing>,
    pub total: u32,
}
