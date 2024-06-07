use crate::api::enclave::{AddSecretRequest, EnclaveApi, EnclaveClient, EnclaveEnv};
use crate::config::{EnclaveConfig, EnclaveConfigError};
use common::api::client::ApiError;
use common::api::papi::{EvApi, EvApiClient};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] ApiError),
    #[error("Error decoding public key — {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("App and team uuid need to be provided in enclave.toml or as args")]
    MissingAppInfo,
    #[error("An error occured during encryption — {0}")]
    EncryptError(ApiError),
    #[error("An error occured reading enclave.toml — {0}")]
    EnclaveConfigError(#[from] EnclaveConfigError),
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
            .map_err(EnvError::EncryptError)?
            .to_string()
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

    if enclave_config.app_uuid.is_none()
        || enclave_config.team_uuid.is_none()
        || enclave_config.uuid.is_none()
    {
        Err(EnvError::MissingAppInfo)
    } else {
        Ok(EnclaveInfo {
            app_uuid: enclave_config.app_uuid.unwrap(),
            team_uuid: enclave_config.team_uuid.unwrap(),
            uuid: enclave_config.uuid.unwrap(),
        })
    }
}
