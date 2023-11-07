use crate::{
    api::cage::{CageDeployment, CagesClient},
    common::CliError,
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

pub async fn restart_cage(
    config: &str,
    cage_uuid: Option<&str>,
    cage_api: &CagesClient,
    _background: bool,
) -> Result<CageDeployment, RestartError> {
    let maybe_cage_uuid = crate::common::resolve_cage_uuid(cage_uuid, config)?;
    let cage_uuid = match maybe_cage_uuid {
        Some(given_cage_uuid) => given_cage_uuid,
        _ => return Err(RestartError::MissingUuid),
    };

    println!("Restarting cage {}...", cage_uuid);

    Ok(cage_api.restart_cage(&cage_uuid).await?)
}
