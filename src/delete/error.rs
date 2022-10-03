use crate::common::CliError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error("An error occurred while reading the cage config — {0}")]
    CageConfigError(#[from] crate::config::CageConfigError),
    #[error("Could not parse uuid from toml")]
    MissingUuid,
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
}

impl CliError for DeleteError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::CageConfigError(config_err) => config_err.exitcode(),
            Self::IoError(_) => exitcode::IOERR,
            Self::ApiError(api_err) => api_err.exitcode(),
            Self::MissingUuid => exitcode::DATAERR,
        }
    }
}
