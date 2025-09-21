use redis::{
    Client, ConnectionAddr, ConnectionInfo, RedisConnectionInfo, aio::MultiplexedConnection,
};

use crate::utilities::{config::Config, errors::AppError};

#[derive(Clone)]
pub struct Redis {
    pub connection: MultiplexedConnection,
}

impl Redis {
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        let connection_info = ConnectionInfo {
            addr: ConnectionAddr::TcpTls {
                host: config.redis_host.as_ref().unwrap().clone(),
                port: *config.redis_port.as_ref().unwrap(),
                insecure: false,
                tls_params: None,
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
