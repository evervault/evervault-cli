use thiserror::Error;

use crate::common::{CliError, OutputPathError};

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("Could not describe eif {0}")]
    DescribeError(#[from] crate::describe::error::DescribeError),
    #[error("Could not build eif {0}")]
    BuildError(#[from] crate::build::error::BuildError),
    #[error("An error occurred while reading the cage config — {0}")]
    CageConfigError(#[from] crate::config::CageConfigError),
    #[error("Failed to access output directory — {0}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error creating zip — {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("An error occurred while uploading to S3 — {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Cage failed to upload - {0}")]
    UploadError(String),
    #[error("Could not read the size of the Cage EIF file {0}")]
    EifSizeReadError(std::io::Error),
    #[error("Could not deploy cage to Evervault Infrastructure")]
    DeploymentError()
}

impl CliError for DeployError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::DescribeError(describe_err) => describe_err.exitcode(),
            Self::BuildError(build_err) => build_err.exitcode(),
            Self::CageConfigError(config_err) => config_err.exitcode(),
            Self::FailedToAccessOutputDir(output_err) => output_err.exitcode(),
            Self::IoError(_) | Self::ZipError(_) | Self::EifSizeReadError(_) => exitcode::IOERR,
            Self::RequestError(_) | Self::UploadError(_) | Self::DeploymentError() => exitcode::TEMPFAIL,
            Self::ApiError(api_err) => api_err.exitcode(),
        }
    }
}
