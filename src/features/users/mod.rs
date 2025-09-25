pub mod handlers;
pub mod models;
pub mod schemas;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::utilities::app_state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/login", post(handlers::login_handler))
        .route("/api/v1/auth/google", get(handlers::google_oauth_handler))
        .route("/api/v1/auth/delete", delete(handlers::delete_user_handler))
        .route(
            "/api/v1/auth/google/callback",
            get(handlers::google_oauth_callback_handler),
        )
}
