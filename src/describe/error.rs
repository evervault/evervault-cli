use crate::docker::error::DockerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DescribeError {
    #[error("Failed to describe enclave image file — {0}")]
    DockerError(#[from] DockerError),
    #[error("Could not find eif at {0}")]
    EIFNotFound(std::path::PathBuf),
}
