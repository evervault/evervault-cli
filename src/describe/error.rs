use crate::common::CliError;
use crate::docker::error::DockerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DescribeError {
    #[error("Failed to describe enclave image file — {0}")]
    DockerError(#[from] DockerError),
    #[error("Could not find eif at {0}")]
    EIFNotFound(std::path::PathBuf),
}

impl CliError for DescribeError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::DockerError(_) => exitcode::UNAVAILABLE,
            Self::EIFNotFound(_) => exitcode::NOINPUT,
        }
    }
}
