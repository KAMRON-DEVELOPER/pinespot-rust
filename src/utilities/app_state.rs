use crate::{
    services::{
        database::Database, google_oauth::GoogleOAuthClient,
        google_oauth_openidconnect::GoogleOAuthOpenIdConnectClient, redis::Redis,
    },
    utilities::config::Config,
};
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use object_store::{aws::AmazonS3, gcp::GoogleCloudStorage};
use reqwest::Client;

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub redis: Redis,
    pub config: Config,
    pub key: Key,
    pub oauth_client: GoogleOAuthClient,
    pub oauth_openidconnect_client: GoogleOAuthOpenIdConnectClient,
    pub http_client: Client,
    pub s3: AmazonS3,
    pub gcs: GoogleCloudStorage,
}

impl FromRef<AppState> for Database {
    fn from_ref(state: &AppState) -> Self {
        state.database.clone()
    }
}

impl FromRef<AppState> for Redis {
    fn from_ref(state: &AppState) -> Self {
        state.redis.clone()
    }
}

impl FromRef<AppState> for Config {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

impl FromRef<AppState> for GoogleOAuthClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

impl FromRef<AppState> for GoogleOAuthOpenIdConnectClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_openidconnect_client.clone()
    }
}
impl FromRef<AppState> for Client {
    fn from_ref(state: &AppState) -> Self {
        state.http_client.clone()
    }
}
impl FromRef<AppState> for AmazonS3 {
    fn from_ref(state: &AppState) -> Self {
        state.s3.clone()
    }
}
impl FromRef<AppState> for GoogleCloudStorage {
    fn from_ref(state: &AppState) -> Self {
        state.gcs.clone()
    }
}
