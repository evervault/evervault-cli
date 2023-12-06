use thiserror::Error;

use crate::common::{CliError, OutputPathError};

#[derive(Debug, Error)]
pub enum DeployError {
    #[error(transparent)]
    DescribeError(#[from] crate::describe::error::DescribeError),
    #[error("Could not build eif {0}")]
    BuildError(#[from] crate::build::error::BuildError),
    #[error("An error occurred while reading the enclave config — {0}")]
    EnclaveConfigError(#[from] crate::config::EnclaveConfigError),
    #[error("Failed to access output directory — {0}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error creating zip — {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("An error occurred while uploading to S3 — {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("An error occured contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Enclave failed to upload - {0}")]
    UploadError(String),
    #[error("Could not read the size of the Enclave EIF file {0}")]
    EifSizeReadError(std::io::Error),
    #[error("Could not deploy enclave to Evervault Infrastructure")]
    DeploymentError,
    #[error("[{0}] Operation timed out after {1} seconds")]
    TimeoutError(String, u64),
}

impl CliError for DeployError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::DescribeError(describe_err) => describe_err.exitcode(),
            Self::BuildError(build_err) => build_err.exitcode(),
            Self::EnclaveConfigError(config_err) => config_err.exitcode(),
            Self::FailedToAccessOutputDir(output_err) => output_err.exitcode(),
            Self::IoError(_) | Self::ZipError(_) | Self::EifSizeReadError(_) => exitcode::IOERR,
            Self::RequestError(_)
            | Self::UploadError(_)
            | Self::DeploymentError
            | Self::TimeoutError(..) => exitcode::TEMPFAIL,
            Self::ApiError(api_err) => api_err.exitcode(),
        }
    }
}
