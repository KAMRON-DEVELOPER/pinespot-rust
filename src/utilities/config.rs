#![allow(unused)]
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use tokio::fs;
use tracing::Level;

#[derive(Clone, Debug)]
pub struct Config {
    pub debug: bool,

    pub tracing_level: Level,

    pub base_dir: PathBuf,

    // DATABASE
    pub database_url: Option<String>,

    // REDIS
    pub redis_host: Option<String>,
    pub redis_port: Option<u16>,
    pub redis_username: Option<String>,
    pub redis_password: Option<String>,

    // FIREBASE ADMIN SDK
    pub firebase_adminsdk: Option<String>,
    pub firebase_adminsdk_path: Option<PathBuf>,

    // GCP
    pub gcp_project_id: Option<String>,
    pub gcs_bucket_name: Option<String>,
    pub gcp_credentials: Option<String>,
    pub gcp_credentials_path: Option<PathBuf>,
    pub google_oauth_client_id: Option<String>,
    pub google_oauth_client_secret: Option<String>,
    pub google_oauth_redirect_url: Option<String>,
    pub key: Option<String>,
    // S3
    pub s3_access_key_id: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub s3_bucket_name: Option<String>,

    // JWT
    pub secret_key: Option<String>,
    pub access_token_expire_in_minute: Option<u32>,
    pub refresh_token_expire_in_days: Option<u32>,

    // EMAIL
    pub email_service_api_key: Option<String>,
}

impl Config {
    pub async fn init() -> Self {
        let base_dir = find_project_root().unwrap_or_else(|| PathBuf::from("."));

        let tracing_level = match get_env("TRACING_LEVEL", Some("ERROR".to_string())) {
            Some(level_string) => match level_string.as_str() {
                "ERROR" => Level::ERROR,
                "INFO" => Level::INFO,
                "DEBUG" => Level::DEBUG,
                "TRACE" => Level::TRACE,
                _ => Level::ERROR,
            },
            None => Level::ERROR,
        };
        // ENV-like values: Docker secrets → env var
        let debug = get_env("DEBUG", Some(false)).unwrap();

        let database_url = get_env(
            "DATABASE_URL",
            Some("postgresql://postgres:password@localhost:5432/pinespot_db".to_string()),
        );

        let redis_host = get_env("REDIS_HOST", Some("localhost".to_string()));
        let redis_port = get_env("REDIS_PORT", Some(6379));
        let redis_username = get_env("REDIS_USERNAME", Some("default".into()));
        let redis_password = get_env("REDIS_PASSWORD", Some("password".to_string()));

        let firebase_adminsdk = get_env("FIREBASE_ADMINSDK", None);

        let gcp_project_id = get_env("GCP_PROJECT_ID", None);
        let gcs_bucket_name = get_env("GCS_BUCKET_NAME", None);
        let gcp_credentials = get_env("GCP_CREDENTIALS", None);
        let google_oauth_client_id = get_env("GOOGLE_OAUTH_CLIENT_ID", None);
        let google_oauth_client_secret = get_env("GOOGLE_OAUTH_CLIENT_SECRET", None);
        let google_oauth_redirect_url = get_env("GOOGLE_OAUTH_REDIRECT_URL", None);
        let key = get_env("KEY", None);

        let s3_access_key_id = get_env("S3_ACCESS_KEY_ID", None);
        let s3_secret_key = get_env("S3_SECRET_KEY", None);
        let s3_endpoint = get_env("S3_ENDPOINT", None);
        let s3_region = get_env("S3_REGION", None);
        let s3_bucket_name = get_env("S3_BUCKET_NAME", None);
        let secret_key = get_env("SECRET_KEY", None);
        let access_token_expire_in_minute = get_env("ACCESS_TOKEN_EXPIRE_IN_MINUTE", Some(15));
        let refresh_token_expire_in_days = get_env("REFRESH_TOKEN_EXPIRE_IN_DAYS", Some(90));
        let email_service_api_key = get_env("EMAIL_SERVICE_API_KEY", None);

        Config {
            debug,
            tracing_level,
            base_dir,
            database_url,
            redis_host,
            redis_port,
            redis_username,
            redis_password,
            firebase_adminsdk,
            firebase_adminsdk_path: None,
            gcp_project_id,
            gcs_bucket_name,
            gcp_credentials,
            gcp_credentials_path: None,
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_redirect_url,
            key,
            s3_access_key_id,
            s3_secret_key,
            s3_endpoint,
            s3_region,
            s3_bucket_name,
            secret_key,
            access_token_expire_in_minute,
            refresh_token_expire_in_days,
            email_service_api_key,
        }
    }
}

fn find_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.toml").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn get_env<T>(name: &str, fallback: Option<T>) -> Option<T>
where
    T: FromStr,
{
    match std::env::var(name) {
        Ok(val) => T::from_str(&val).ok(),
        Err(_) => fallback,
    }
}
