use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error("An error occurred while reading the cage config — {0}")]
    CageConfigError(#[from] crate::config::CageConfigError),
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Cage failed to delete - {0}")]
    DeletionError(String),
}
