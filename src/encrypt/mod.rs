use rust_crypto::{
    backend::{ies_secp256k1_openssl, ies_secp256r1_openssl, CryptoClient, Datatype},
    EvervaultCryptoError,
};
use thiserror::Error;

use crate::{
    api::{cage::CagesClient, AuthMode},
    cli::encrypt::CurveName,
};

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Could not find signing key file at {0}")]
    SigningKeyNotFound(String),
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Error decoding public key — {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("An error occurred during decryption — {0}")]
    EvervaultCryptoError(#[from] EvervaultCryptoError),
}

pub async fn encrypt(
    value: String,
    team_uuid: String,
    app_uuid: String,
    curve: CurveName,
) -> Result<String, EncryptError> {
    let cage_api = CagesClient::new(AuthMode::NoAuth);
    //let keys = cage_api.get_app_keys(&team_uuid, &app_uuid).await?;

    let result = match curve {
        CurveName::Nist => {
            let client = ies_secp256r1_openssl::Client::new(
                ies_secp256r1_openssl::EcKey::public_key_from_bytes(&base64::decode(
                    "Aw9aPPL6XhmvEXkM6Lb0A/mXLVEb5Vs5WeuHTtvQBAi7".to_string(),
                )?)?,
            );
            client.encrypt(value, Datatype::String, false)?
        }
        CurveName::Koblitz => {
            let client = ies_secp256k1_openssl::Client::new(
                ies_secp256k1_openssl::EcKey::public_key_from_bytes(&base64::decode(
                    "Aw9aPPL6XhmvEXkM6Lb0A/mXLVEb5Vs5WeuHTtvQBAi7".to_string(),
                )?)?,
            );
            client.encrypt(value, Datatype::String, false)?
        }
    };

    Ok(result)
}
