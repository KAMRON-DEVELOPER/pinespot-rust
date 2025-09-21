use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::utilities::{config::Config, errors::AppError};

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        let options: PgConnectOptions = config
            .database_url
            .as_ref()
            .unwrap()
            .parse()
            .map_err(|_| AppError::DatabaseParsingError)?;

        let pool = PgPoolOptions::new()
            .max_connections(100)
            .connect_with(options)
            .await?;

        Ok(Self { pool })
    }
}
