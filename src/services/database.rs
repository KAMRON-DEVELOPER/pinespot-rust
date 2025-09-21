use rustls::ClientConfig;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::str::FromStr;
use std::sync::Arc;

use crate::utilities::{config::Config, errors::AppError};

#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
}

impl Database {
    pub async fn new(
        config: &Config,
        tls_config: Option<Arc<ClientConfig>>,
    ) -> Result<Self, AppError> {
        // Create a custom TLS connector for sqlx
        let tls_connector = tokio_rustls::TlsConnector::from(tls_config);

        let options: PgConnectOptions = config
            .database_url
            .as_ref()
            .unwrap()
            .parse()
            .map_err(|_| AppError::DatabaseParsingError)?;

        let a = PgConnectOptions::from_str(config.database_url.as_ref().unwrap());

        let pool = PgPoolOptions::new()
            .max_connections(100)
            .connect_with(options)
            .await?;

        Ok(Self { pool })
    }
}
