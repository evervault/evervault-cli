use crate::{
    api::{self, AuthMode},
    common::CliError,
    config::{CageConfig, CageConfigError},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RestartError {
    #[error("An error occurred while reading the cage config — {0}")]
    CageConfigError(#[from] crate::config::CageConfigError),
    #[error("No Cage Uuid given. You can provide one by using either the --cage-uuid flag, or using the --config flag to point to a Cage.toml")]
    MissingUuid,
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
}

impl CliError for RestartError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::CageConfigError(config_err) => config_err.exitcode(),
            Self::IoError(_) => exitcode::IOERR,
            Self::ApiError(api_err) => api_err.exitcode(),
            Self::MissingUuid => exitcode::DATAERR,
        }
    }
}

fn resolve_cage_uuid(
    given_uuid: Option<&str>,
    config_path: &str,
) -> Result<Option<String>, CageConfigError> {
    if let Some(given_uuid) = given_uuid {
        return Ok(Some(given_uuid.to_string()));
    }
    let config = CageConfig::try_from_filepath(config_path)?;
    Ok(config.uuid)
}

pub async fn restart_cage(
    config: &str,
    cage_uuid: Option<&str>,
    api_key: &str,
    _background: bool, // TODO(Mark): implement cage restart polling
) -> Result<(), RestartError> {
    let maybe_cage_uuid = resolve_cage_uuid(cage_uuid, config)?;
    let cage_uuid = match maybe_cage_uuid {
        Some(given_cage_uuid) => given_cage_uuid,
        _ => return Err(RestartError::MissingUuid),
    };

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    match cage_api.restart_cage(&cage_uuid).await {
        Ok(_) => Ok(()),
        Err(e) => {
            return Err(RestartError::ApiError(e));
        }
    }
}
