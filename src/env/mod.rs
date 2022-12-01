use crate::api::cage::{AddSecretRequest, CageEnv, CagesClient};
use crate::cli::env::EnvCommands;
use crate::config::{CageConfig, CageConfigError};
use crate::encrypt::{self, encrypt};
use rust_crypto::EvervaultCryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Error decoding public key — {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("An error occurred during decryption — {0}")]
    EvervaultCryptoError(#[from] EvervaultCryptoError),
    #[error("App and team uuid need to be provided in cage.toml or as args")]
    MissingAppInfo,
    #[error("An error occured during enryption — {0}")]
    EncryptError(#[from] encrypt::EncryptError),
    #[error("An error occured reading cage.toml — {0}")]
    CageConfigError(#[from] CageConfigError),
}

pub async fn env(client: CagesClient, action: EnvCommands) -> Result<Option<CageEnv>, EnvError> {
    match action {
        EnvCommands::Add(command) => {
            let details = get_cage_details(command.config)?;
            let env_secret = if command.skip_encryption {
                command.secret
            } else {
                encrypt(
                    command.secret,
                    details.team_uuid,
                    details.app_uuid,
                    command.curve,
                )
                .await?
            };

            let request = AddSecretRequest {
                name: command.name,
                secret: env_secret,
            };
            client.add_env_var(details.uuid, request).await?;
            Ok(None)
        }
        EnvCommands::Delete(command) => {
            let details = get_cage_details(command.config)?;
            client.delete_env_var(details.uuid, command.name).await?;
            Ok(None)
        }
        EnvCommands::Get(command) => {
            let details = get_cage_details(command.config)?;
            Ok(Some(client.get_cage_env(details.uuid).await?))
        }
    }
}

pub struct CageInfo {
    pub uuid: String,
    pub team_uuid: String,
    pub app_uuid: String,
}

fn get_cage_details(config_path: String) -> Result<CageInfo, EnvError> {
    let cage_config = CageConfig::try_from_filepath(&config_path)?;

    if cage_config.app_uuid.is_none()
        || cage_config.team_uuid.is_none()
        || cage_config.uuid.is_none()
    {
        return Err(EnvError::MissingAppInfo);
    } else {
        Ok(CageInfo {
            app_uuid: cage_config.app_uuid.unwrap(),
            team_uuid: cage_config.team_uuid.unwrap(),
            uuid: cage_config.uuid.unwrap(),
        })
    }
}
