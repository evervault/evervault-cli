use crate::api::cage::{AddSecretRequest, CagesClient, CageEnv};
use crate::cli::encrypt::CurveName;
use crate::cli::env::Action;
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

pub async fn env(
    name: String,
    secret: String,
    config_path: String,
    curve: CurveName,
    client: CagesClient,
    action: Action,
) -> Result<Option<CageEnv>, EnvError> {
    let cage_config = CageConfig::try_from_filepath(&config_path)?;

    let (app_uuid, team_uuid) = if cage_config.app_uuid.is_none() || cage_config.team_uuid.is_none()
    {
        return Err(EnvError::MissingAppInfo);
    } else {
        (
            cage_config.app_uuid.unwrap(),
            cage_config.team_uuid.unwrap(),
        )
    };

    match action {
        Action::Add => {
            let encrypted_secret =
                encrypt(secret.clone(), team_uuid.clone(), app_uuid.clone(), curve).await?;
            let request = AddSecretRequest {
                name,
                secret: encrypted_secret,
            };
            client
                .add_env_var(cage_config.uuid.unwrap(), request)
                .await?;
            Ok(None)        
        }
        Action::Delete => {
            client
                .delete_env_var(cage_config.uuid.unwrap(), name)
                .await?;
            Ok(None)    
        }
        Action::Get => {
            Ok(Some(client.get_cage_env(cage_config.uuid.unwrap()).await?))
        }
    }
}
