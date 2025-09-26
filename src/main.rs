// Modules
pub mod features;
pub mod services;
pub mod utilities;

// Crates bring to current scope
use std::net::SocketAddr;
use std::result::Result::Ok;

use axum::{
    extract::{ConnectInfo, MatchedPath, Request},
    http::{HeaderValue, Method, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::cookie::Key;
use tokio::signal;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

use crate::{
    features::{listings, users},
    services::{
        database::Database,
        google_oauth::build_google_oauth_client,
        google_oauth_openidconnect::build_google_oauth_openidconnect_client,
        redis::Redis,
        s3::{build_gcs, build_s3},
    },
    utilities::{app_state::AppState, config::Config},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match dotenvy::dotenv() {
        Ok(path) => {
            info!("Loaded .env file from {}", path.display());
        }
        Err(dotenvy::Error::Io(ref err)) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(".env file not found, continuing without it");
        }
        Err(e) => {
            tracing::warn!("Couldn't load .env file: {}", e);
        }
    }

    let config = Config::init().await;

    tracing_subscriber::fmt()
        .with_max_level(config.tracing_level)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(false)
        .init();

    // let tls_config = build_tls_config(&config)?;
    // let shared_tls_config = tls_config;
    let database = Database::new(&config).await?;
    let redis = Redis::new(&config).await?;
    let key = Key::from(config.key.as_ref().unwrap().as_bytes());
    let oauth_client = build_google_oauth_client(&config)?;
    let oauth_openidconnect_client = build_google_oauth_openidconnect_client(&config).await?;
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let s3 = build_s3(&config)?;
    let gcs = build_gcs(&config)?;

    let app_state = AppState {
        database,
        redis,
        config,
        key,
        oauth_client,
        oauth_openidconnect_client,
        http_client,
        s3,
        gcs,
    };

    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_str("http://127.0.0.1:3000").unwrap(),
            HeaderValue::from_str("http://127.0.0.1:5173").unwrap(),
            HeaderValue::from_str("https://pinespot.uz").unwrap(),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);

    // Build router
    let app = axum::Router::new()
        .merge(listings::routes())
        .merge(users::routes())
        .fallback(not_found_handler)
        .layer(
            TraceLayer::new_for_http()
                // Create our own span for the request and include the matched path. The matched
                // path is useful for figuring out which handler the request was routed to.
                .make_span_with(|req: &Request| {
                    let method = req.method();
                    let uri = req.uri();

                    // axum automatically adds this extension.
                    let matched_path = req
                        .extensions()
                        .get::<MatchedPath>()
                        .map(|matched_path| matched_path.as_str());

                    tracing::debug_span!("request", %method, %uri, matched_path)
                })
                // By default `TraceLayer` will log 5xx responses but we're doing our specific
                // logging of errors so disable that
                .on_failure(()),
        )
        .with_state(app_state)
        .layer(cors);

    // Run Axum server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8001));
    info!("Starting server on {:#?}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();

    Ok(())
}

async fn not_found_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    println!("Client with {} connected", addr);
    (StatusCode::NOT_FOUND, "nothing to see here")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
