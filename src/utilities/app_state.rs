use crate::{
    services::{database::Database, google_oauth::GoogleOAuthClient, redis::Redis},
    utilities::config::Config,
};
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub redis: Redis,
    pub config: Config,
    pub key: Key,
    pub client: GoogleOAuthClient,
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
        state.client.clone()
    }
}
