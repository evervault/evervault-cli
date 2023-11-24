use crate::config::CageConfigError;
use crate::{
    api::{
        cage::{CageApi, CagesClient},
        AuthMode,
    },
    cli::encrypt::CurveName,
};
use rust_crypto::{
    backend::{ies_secp256k1_openssl, ies_secp256r1_openssl, CryptoClient, Datatype},
    EvervaultCryptoError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Team uuid and app uuid must be provided as arg or in cage toml")]
    MissingUuid,
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Error decoding public key — {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("An error occurred during decryption — {0}")]
    EvervaultCryptoError(#[from] EvervaultCryptoError),
    #[error("An error occured reading cage.toml — {0}")]
    CageConfigError(#[from] CageConfigError),
}

pub async fn encrypt(
    value: String,
    team_uuid: String,
    app_uuid: String,
    curve: CurveName,
) -> Result<String, EncryptError> {
    let cage_api = CagesClient::new(AuthMode::NoAuth);
    let keys = cage_api.get_app_keys(&team_uuid, &app_uuid).await?;

    let result = match curve {
        CurveName::Nist | CurveName::Secp256r1 => {
            let client = ies_secp256r1_openssl::Client::new(
                ies_secp256r1_openssl::EcKey::public_key_from_bytes(&base64::decode(
                    keys.ecdh_p256_key,
                )?)?,
            );
            client.encrypt(value, Datatype::String, false)?
        }
        CurveName::Koblitz | CurveName::Secp256k1 => {
            let client = ies_secp256k1_openssl::Client::new(
                ies_secp256k1_openssl::EcKey::public_key_from_bytes(&base64::decode(
                    keys.ecdh_key,
                )?)?,
            );
            client.encrypt(value, Datatype::String, false)?
        }
    };

    Ok(result)
}
