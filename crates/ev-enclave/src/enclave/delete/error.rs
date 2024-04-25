use crate::enclave::{api, common::CliError, config};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeleteError {
    #[error("An error occurred while reading the Enclave config — {0}")]
    EnclaveConfigError(#[from] config::EnclaveConfigError),
    #[error("No Enclave Uuid given. You can provide one by using either the --enclave-uuid flag, or using the --config flag to point to an Enclave.toml")]
    MissingUuid,
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] api::client::ApiError),
}

impl CliError for DeleteError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::EnclaveConfigError(config_err) => config_err.exitcode(),
            Self::IoError(_) => exitcode::IOERR,
            Self::ApiError(api_err) => api_err.exitcode(),
            Self::MissingUuid => exitcode::DATAERR,
        }
    }
}
