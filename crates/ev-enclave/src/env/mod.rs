use crate::api::enclave::{AddSecretRequest, EnclaveApi, EnclaveClient, EnclaveEnv};
use crate::cli::env::EnvCommands;
use crate::config::{EnclaveConfig, EnclaveConfigError};
use crate::encrypt::{self, encrypt};
#[cfg(feature = "internal_dependency")]
use rust_crypto::EvervaultCryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Error decoding public key — {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("An error occurred during decryption — {0}")]
    EvervaultCryptoError(#[from] EvervaultCryptoError),
    #[error("App and team uuid need to be provided in enclave.toml or as args")]
    MissingAppInfo,
    #[error("An error occured during encryption — {0}")]
    EncryptError(#[from] encrypt::EncryptError),
    #[error("An error occured reading enclave.toml — {0}")]
    EnclaveConfigError(#[from] EnclaveConfigError),
}

pub async fn env(
    client: EnclaveClient,
    action: EnvCommands,
) -> Result<Option<EnclaveEnv>, EnvError> {
    match action {
        EnvCommands::Add(command) => {
            let details = get_enclave_details(command.config)?;
            let env_value = if command.is_secret {
                encrypt(
                    command.value,
                    details.team_uuid,
                    details.app_uuid,
                    command.curve,
                )
                .await?
            } else {
                command.value
            };

            let request = AddSecretRequest {
                name: command.name,
                secret: env_value,
            };
            client.add_env_var(details.uuid, request).await?;
            Ok(None)
        }
        EnvCommands::Delete(command) => {
            let details = get_enclave_details(command.config)?;
            client.delete_env_var(details.uuid, command.name).await?;
            Ok(None)
        }
        EnvCommands::Get(command) => {
            let details = get_enclave_details(command.config)?;
            Ok(Some(client.get_enclave_env(details.uuid).await?))
        }
    }
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
