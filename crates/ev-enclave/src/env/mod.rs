use crate::api::enclave::{AddSecretRequest, EnclaveApi, EnclaveClient, EnclaveEnv};
use crate::config::{EnclaveConfig, EnclaveConfigError};
use common::api::client::ApiError;
use common::api::papi::{EvApi, EvApiClient};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] ApiError),
    #[error("App, team and cage uuid need to be provided in enclave.toml or as args")]
    MissingAppInfo,
    #[error("An error occured during encryption — {0}")]
    EncryptError(ApiError),
    #[error("An error occured reading enclave.toml — {0}")]
    EnclaveConfigError(#[from] EnclaveConfigError),
    #[error("The computed secret value is invalid, please contact Evervault support.")]
    InvalidSecretValueError,
}

fn unwrap_serde_string(val: serde_json::Value) -> Result<String, EnvError> {
    match val {
        serde_json::Value::String(val_str) => Ok(val_str),
        _ => Err(EnvError::InvalidSecretValueError),
    }
}

pub async fn add_env_var(
    client: EnclaveClient,
    papi_client: EvApiClient,
    config_path: String,
    key: String,
    value: String,
    is_secret: bool,
) -> Result<Option<EnclaveEnv>, EnvError> {
    let details = get_enclave_details(config_path)?;

    let env_value = if is_secret {
        papi_client
            .encrypt(value.into())
            .await
            .map_err(EnvError::EncryptError)
            .and_then(unwrap_serde_string)?
    } else {
        value
    };

    client
        .add_env_var(
            details.uuid,
            AddSecretRequest {
                name: key,
                secret: env_value,
            },
        )
        .await?;
    Ok(None)
}

pub async fn delete_env_var(
    client: EnclaveClient,
    config_path: String,
    key: String,
) -> Result<Option<EnclaveEnv>, EnvError> {
    let details = get_enclave_details(config_path)?;

    client.delete_env_var(details.uuid, key).await?;

    Ok(None)
}

pub async fn get_env_vars(
    client: EnclaveClient,
    config_path: String,
) -> Result<Option<EnclaveEnv>, EnvError> {
    let details = get_enclave_details(config_path)?;

    Ok(Some(client.get_enclave_env(details.uuid).await?))
}

pub struct EnclaveInfo {
    pub uuid: String,
    pub team_uuid: String,
    pub app_uuid: String,
}

fn get_enclave_details(config_path: String) -> Result<EnclaveInfo, EnvError> {
    let enclave_config = EnclaveConfig::try_from_filepath(&config_path)?;

    let app_uuid = enclave_config.app_uuid.ok_or(EnvError::MissingAppInfo)?;
    let team_uuid = enclave_config.team_uuid.ok_or(EnvError::MissingAppInfo)?;
    let uuid = enclave_config.uuid.ok_or(EnvError::MissingAppInfo)?;

    Ok(EnclaveInfo {
        app_uuid,
        team_uuid,
        uuid,
    })
}
