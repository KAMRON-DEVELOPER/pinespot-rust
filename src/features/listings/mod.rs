pub mod handlers;
pub mod models;
pub mod schemas;

use axum::{
    Router,
    routing::{delete, get},
};

use crate::utilities::app_state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/listings", get(handlers::get_many_listings_handler))
        .route("/listings/:id", get(handlers::get_one_listing_handler))
        .route("/listings/:id", delete(handlers::delete_listing_handler))
}
