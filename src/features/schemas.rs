use serde::Deserialize;

use crate::utilities::errors::AppError;

#[derive(Deserialize, Debug)]
pub struct Pagination {
    #[serde(default = "default_offset")]
    pub offset: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_offset() -> i64 {
    0
}

fn default_limit() -> i64 {
    20
}

impl Pagination {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.offset < 0 {
            return Err(AppError::ValidationError(
                "Offset must positive".to_string(),
            ));
        }

        if self.limit < 0 {
            return Err(AppError::ValidationError("Limit must positive".to_string()));
        } else if self.limit == 0 {
            return Err(AppError::ValidationError(
                "Limit must not be zero!".to_string(),
            ));
        }

        Ok(())
    }
}
