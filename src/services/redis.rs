use crate::utilities::{config::Config, errors::AppError};
use redis::{Client, ClientTlsConfig, TlsCertificates, aio::MultiplexedConnection};

#[derive(Clone)]
pub struct Redis {
    pub connection: MultiplexedConnection,
}

impl Redis {
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        // Structure to hold mTLS client certificate and key binaries in PEM format
        let client_tls = ClientTlsConfig {
            client_cert: config.client_cert.as_ref().unwrap().as_bytes().to_vec(),
            client_key: config.client_key.as_ref().unwrap().as_bytes().to_vec(),
        };

        // Structure to hold TLS certificates
        // * client_tls: binaries of clientkey and certificate within a ClientTlsConfig structure if mTLS is used
        // * root_cert: binary CA certificate in PEM format if CA is not in local truststore
        let tls_certs = TlsCertificates {
            client_tls: Some(client_tls),
            root_cert: None,
        };

        let client = Client::build_with_tls("redis://host:port/db", tls_certs)?;

        let connection_info = client.get_connection_info();
        println!(">>> connection info: {connection_info:?}");
        println!(">>> connection info: {connection_info:?}");

        let connection = client.get_multiplexed_tokio_connection().await?;

        Ok(Self { connection })
    }
}
