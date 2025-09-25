use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::gcp::{GoogleCloudStorage, GoogleCloudStorageBuilder};

use crate::utilities::{config::Config, errors::AppError};

pub fn build_s3(config: &Config) -> Result<AmazonS3, AppError> {
    Ok(AmazonS3Builder::new()
        .with_region(config.s3_region.clone().unwrap())
        .with_bucket_name(config.s3_bucket_name.clone().unwrap())
        .with_access_key_id(config.s3_access_key_id.clone().unwrap())
        .with_secret_access_key(config.s3_secret_key.clone().unwrap())
        .with_url(config.s3_endpoint.clone().unwrap())
        .build()?)
}

pub fn build_gcs(config: &Config) -> Result<GoogleCloudStorage, AppError> {
    if let Some(binding) = config.gcp_credentials_path.clone() {
        if binding.exists() {
            let service_account_path = binding.to_str().unwrap();

            return Ok(GoogleCloudStorageBuilder::new()
                .with_service_account_path(service_account_path)
                .build()?);
        }
    }

    Err(AppError::MissingCredentials)
}
