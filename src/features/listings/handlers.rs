use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use uuid::Uuid;

use crate::{
    features::{
        listings::{models::Listing, schemas::ListingResponse},
        schemas::Pagination,
    },
    services::database::Database,
    utilities::{errors::AppError, session::Session},
};

#[axum::debug_handler]
pub async fn get_many_listings_handler(
    State(database): State<Database>,
    session: Session,
    Query(pagination): Query<Pagination>,
) -> Result<impl IntoResponse, AppError> {
    pagination.validate()?;

    let listings = sqlx::query_as!(
        Listing,
        r#"
            SELECT * FROM listings where owner_id = $1
            ORDER BY updated_at DESC
            OFFSET $2 LIMIT $3
        "#,
        session.user_id,
        pagination.offset,
        pagination.limit
    )
    .fetch_all(&database.pool)
    .await?;

    Ok(Json(ListingResponse {
        listings,
        total: 1000,
    }))
}

#[axum::debug_handler]
pub async fn get_one_listing_handler(
    State(database): State<Database>,
    session: Session,
    Path(listing_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let listing = sqlx::query_as!(
        Listing,
        r#"
            SELECT * FROM listings where owner_id = $1 AND id = $2
        "#,
        session.user_id,
        listing_id
    )
    .fetch_one(&database.pool)
    .await?;

    Ok(Json(listing))
}

pub async fn delete_listing_handler(
    session: Session,
    Path(listing_id): Path<Uuid>,
    State(database): State<Database>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query_scalar!(
        r#"
            DELETE FROM listings where owner_id = $1 AND id = $2
        "#,
        session.user_id,
        listing_id
    )
    .execute(&database.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
