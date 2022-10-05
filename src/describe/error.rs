use crate::common::CliError;
use crate::docker::error::DockerError;
use crate::enclave::error::EnclaveError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DescribeError {
    #[error("Failed to describe enclave image file — {0}")]
    DockerError(#[from] DockerError),
    #[error("Could not find eif at {0}")]
    EIFNotFound(std::path::PathBuf),
    #[error(transparent)]
    EnclaveError(#[from] EnclaveError),
}

impl CliError for DescribeError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::DockerError(_) => exitcode::UNAVAILABLE,
            Self::EIFNotFound(_) => exitcode::NOINPUT,
            Self::EnclaveError(inner) => inner.exitcode(),
        }
    }
}
