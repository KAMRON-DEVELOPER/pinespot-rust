use crate::utilities::{config::Config, errors::AppError};
use redis::{
    Client, ClientTlsConfig, ConnectionAddr, ConnectionInfo, RedisConnectionInfo, TlsCertificates,
    aio::MultiplexedConnection,
};
use tracing::debug;

#[derive(Clone)]
pub struct Redis {
    pub connection: MultiplexedConnection,
}

impl Redis {
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        let redis_url = config
            .redis_url
            .clone()
            .ok_or(AppError::RedisUrlNotSetError)?;

        if let Some(client_cert) = &config.client_cert
            && let Some(client_key) = &config.client_key
        {
            // Structure to hold mTLS client certificate and key binaries in PEM format
            let client_tls = ClientTlsConfig {
                client_cert: client_cert.as_bytes().to_vec(),
                client_key: client_key.as_bytes().to_vec(),
            };

            // Structure to hold TLS certificates
            // * client_tls: binaries of clientkey and certificate within a ClientTlsConfig structure if mTLS is used
            // * root_cert: binary CA certificate in PEM format if CA is not in local truststore
            let tls_certs = TlsCertificates {
                client_tls: Some(client_tls),
                root_cert: None,
            };

            let _conn_info = ConnectionInfo {
                addr: ConnectionAddr::Tcp(
                    config.redis_host.clone().unwrap(),
                    config.redis_port.unwrap(),
                ),
                redis: RedisConnectionInfo {
                    db: 0,
                    username: config.redis_username.clone(),
                    password: config.redis_password.clone(),
                    ..Default::default()
                },
            };

            let client = Client::build_with_tls(redis_url, tls_certs)?;

            let connection_info = client.get_connection_info();
            debug!(">>> connection info: {connection_info:?}");

            let connection = client.get_multiplexed_tokio_connection().await?;

            return Ok(Self { connection });
        }
        let client = Client::open(redis_url)?;

        let connection_info = client.get_connection_info();
        debug!(">>> connection info: {connection_info:#?}");

        let connection = client.get_multiplexed_tokio_connection().await?;

        Ok(Self { connection })
    }
}
