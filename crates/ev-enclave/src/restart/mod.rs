use crate::{
    api::enclave::{EnclaveApi, EnclaveClient, EnclaveDeployment},
    common::CliError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RestartError {
    #[error("An error occurred while reading the Enclave config — {0}")]
    EnclaveConfigError(#[from] crate::config::EnclaveConfigError),
    #[error("No Enclave Uuid given. You can provide one by using either the --enclave-uuid flag, or using the --config flag to point to an Enclave.toml")]
    MissingUuid,
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
}

impl CliError for RestartError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::EnclaveConfigError(config_err) => config_err.exitcode(),
            Self::IoError(_) => exitcode::IOERR,
            Self::ApiError(api_err) => api_err.exitcode(),
            Self::MissingUuid => exitcode::DATAERR,
        }
    }
}

pub async fn restart_enclave(
    config: &str,
    enclave_uuid: Option<&str>,
    enclave_api: &EnclaveClient,
    _background: bool,
) -> Result<EnclaveDeployment, RestartError> {
    let maybe_enclave_uuid = crate::common::resolve_enclave_uuid(enclave_uuid, config)?;
    let enclave_uuid = match maybe_enclave_uuid {
        Some(given_enclave_uuid) => given_enclave_uuid,
        _ => return Err(RestartError::MissingUuid),
    };

    println!("Restarting Enclave {}...", enclave_uuid);

    Ok(enclave_api.restart_enclave(&enclave_uuid).await?)
}
