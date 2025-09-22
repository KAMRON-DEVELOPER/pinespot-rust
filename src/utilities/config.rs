#![allow(unused)]
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use sqlx::postgres::PgSslMode;
use tokio::fs;
use tracing::{Level, warn};

#[derive(Clone, Debug)]
pub struct Config {
    pub base_dir: PathBuf,
    pub debug: bool,
    pub tracing_level: Level,

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

    // SSL/TLS
    pub ca: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub client_cert: Option<String>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key: Option<String>,
    pub client_key_path: Option<PathBuf>,
    pub ssl_mode: Option<PgSslMode>,
}

impl Config {
    pub async fn init() -> Self {
        let base_dir = find_project_root().unwrap_or_else(|| PathBuf::from("."));

        let debug = get_config_value("DEBUG", Some("DEBUG"), None, Some(false))
            .await
            .unwrap();
        let tracing_level = get_config_value(
            "TRACING_LEVEL",
            Some("TRACING_LEVEL"),
            None,
            Some(Level::DEBUG),
        )
        .await
        .unwrap();

        let database_url = get_config_value(
            "DATABASE_URL",
            Some("DATABASE_URL"),
            None,
            Some("postgresql://postgres:password@localhost:5432/pinespot_db".to_string()),
        )
        .await;

        let redis_host = get_config_value(
            "REDIS_HOST",
            Some("REDIS_HOST"),
            None,
            Some("localhost".to_string()),
        )
        .await;
        let redis_port = get_config_value("REDIS_PORT", None, None, Some(6379)).await;
        let redis_username = get_config_value(
            "REDIS_USERNAME",
            Some("REDIS_USERNAME"),
            None,
            Some("default".into()),
        )
        .await;
        let redis_password = get_config_value(
            "REDIS_PASSWORD",
            Some("REDIS_PASSWORD"),
            None,
            Some("password".to_string()),
        )
        .await;

        let firebase_adminsdk_path = base_dir.join("certs/firebase-adminsdk.json");
        let firebase_adminsdk = get_config_value(
            "firebase-adminsdk.json",
            Some("FIREBASE_ADMINSDK"),
            Some(&firebase_adminsdk_path),
            None,
        )
        .await;

        let gcp_project_id =
            get_config_value("GCP_PROJECT_ID", Some("GCP_PROJECT_ID"), None, None).await;
        let gcs_bucket_name =
            get_config_value("GCS_BUCKET_NAME", Some("GCS_BUCKET_NAME"), None, None).await;
        let gcp_credentials_path = base_dir.join("certs/client/gcp-credentials.json");
        let gcp_credentials = get_config_value(
            "gcp-credentials.json",
            Some("GCP_CREDENTIALS"),
            Some(&gcp_credentials_path),
            None,
        )
        .await;
        let google_oauth_client_id = get_config_value(
            "GOOGLE_OAUTH_CLIENT_ID",
            Some("GOOGLE_OAUTH_CLIENT_ID"),
            None,
            None,
        )
        .await;
        let google_oauth_client_secret = get_config_value(
            "GOOGLE_OAUTH_CLIENT_SECRET",
            Some("GOOGLE_OAUTH_CLIENT_SECRET"),
            None,
            None,
        )
        .await;
        let google_oauth_redirect_url = get_config_value(
            "GOOGLE_OAUTH_REDIRECT_URL",
            Some("GOOGLE_OAUTH_REDIRECT_URL"),
            None,
            None,
        )
        .await;
        let key = get_config_value("KEY", Some("KEY"), None, None).await;

        let s3_access_key_id =
            get_config_value("S3_ACCESS_KEY_ID", Some("S3_ACCESS_KEY_ID"), None, None).await;
        let s3_secret_key =
            get_config_value("S3_SECRET_KEY", Some("S3_SECRET_KEY"), None, None).await;
        let s3_endpoint = get_config_value("S3_ENDPOINT", Some("S3_ENDPOINT"), None, None).await;
        let s3_region = get_config_value("S3_REGION", Some("S3_REGION"), None, None).await;
        let s3_bucket_name =
            get_config_value("S3_BUCKET_NAME", Some("S3_BUCKET_NAME"), None, None).await;
        let secret_key = get_config_value("SECRET_KEY", Some("SECRET_KEY"), None, None).await;
        let access_token_expire_in_minute = get_config_value(
            "ACCESS_TOKEN_EXPIRE_IN_MINUTE",
            Some("ACCESS_TOKEN_EXPIRE_IN_MINUTE"),
            None,
            Some(15),
        )
        .await;
        let refresh_token_expire_in_days = get_config_value(
            "REFRESH_TOKEN_EXPIRE_IN_DAYS",
            Some("REFRESH_TOKEN_EXPIRE_IN_DAYS"),
            None,
            Some(90),
        )
        .await;
        let email_service_api_key = get_config_value(
            "EMAIL_SERVICE_API_KEY",
            Some("EMAIL_SERVICE_API_KEY"),
            None,
            None,
        )
        .await;

        // TLS certs: Docker secrets → fallback path
        let ca_path = base_dir.join("certs/ca/ca.pem");
        let ca = get_config_value("ca.pem", Some("CA"), Some(&ca_path), None).await;
        let client_cert_path = base_dir.join("certs/client/client-cert.pem");
        let client_cert = get_config_value(
            "client-cert.pem",
            Some("CLIENT_CERT"),
            Some(&client_cert_path),
            None,
        )
        .await;
        let client_key_path = base_dir.join("certs/client/client-key.pem");
        let client_key = get_config_value(
            "client-key.pem",
            Some("CLIENT_KEY"),
            Some(&client_key_path),
            None,
        )
        .await;

        let ssl_mode =
            get_config_value("ssl_mode", Some("SSL_MODE"), None, Some(PgSslMode::Disable)).await;

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
            firebase_adminsdk_path: Some(firebase_adminsdk_path),
            gcp_project_id,
            gcs_bucket_name,
            gcp_credentials,
            gcp_credentials_path: Some(gcp_credentials_path),
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
            ca_path: Some(ca_path),
            ca,
            client_cert_path: Some(client_cert_path),
            client_cert,
            client_key_path: Some(client_key_path),
            client_key,
            ssl_mode,
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

/// Try to resolve config value from Docker secrets, file path, or env var.
/// - `secret_name` → filename inside `/run/secrets/`
/// - `env_name` → optional environment variable key
/// - `fallback_path` → fallback file path (checked if exists)
///
/// Returns parsed `T` if found and successfully parsed.
pub async fn get_config_value<T>(
    secret_name: &str,
    env_name: Option<&str>,
    fallback_path: Option<&PathBuf>,
    fallback: Option<T>,
) -> Option<T>
where
    T: FromStr,
{
    // 1. Docker secrets
    let docker_secret = Path::new("/run/secrets").join(secret_name);
    if docker_secret.exists() {
        match fs::read_to_string(&docker_secret).await {
            Ok(content) => {
                if let Ok(parsed) = T::from_str(content.trim()) {
                    return Some(parsed);
                }
            }
            Err(e) => warn!(
                "Failed to read docker secret {}: {}",
                docker_secret.display(),
                e
            ),
        }
    }

    // 2. Fallback file path
    if let Some(path) = fallback_path
        && path.exists()
    {
        match fs::read_to_string(path).await {
            Ok(content) => {
                if let Ok(parsed) = T::from_str(content.trim()) {
                    return Some(parsed);
                }
            }
            Err(e) => warn!("Failed to read fallback file {}: {}", path.display(), e),
        }
    }

    // 3. Env var
    if let Some(env_key) = env_name
        && let Ok(val) = std::env::var(env_key)
        && let Ok(parsed) = T::from_str(val.trim())
    {
        return Some(parsed);
    }

    // 4. Final fallback
    fallback
}
