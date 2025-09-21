use std::sync::Arc;

use redis::{
    Client, ClientTlsConfig, ConnectionAddr, ConnectionInfo, RedisConnectionInfo,
    aio::MultiplexedConnection,
};
use rustls::ClientConfig;

use crate::utilities::{config::Config, errors::AppError};

#[derive(Clone)]
pub struct Redis {
    pub connection: MultiplexedConnection,
}

impl Redis {
    pub async fn new(
        config: &Config,
        tls_config: Option<Arc<ClientConfig>>,
    ) -> Result<Self, AppError> {
        // Create the Redis-specific TLS configuration
        let client_tls_config = ClientTlsConfig {
            client_cert: config.client_cert.as_ref().unwrap().as_bytes().to_vec(),
            client_key: config.client_key.as_ref().unwrap().as_bytes().to_vec(),
        };

        let connection_info = ConnectionInfo {
            addr: ConnectionAddr::TcpTls {
                host: config.redis_host.as_ref().unwrap().clone(),
                port: *config.redis_port.as_ref().unwrap(),
                insecure: false,
                tls_params: client_tls_config,
            },
            redis: RedisConnectionInfo {
                db: 0,
                username: config.redis_username.clone(),
                password: config.redis_password.clone(),
                protocol: redis::ProtocolVersion::RESP3,
            },
        };

        let client = Client::open(connection_info)?;

        let connection = client.get_multiplexed_tokio_connection().await?;

        Ok(Self { connection })
    }
}
