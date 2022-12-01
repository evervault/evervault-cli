use rust_crypto::EvervaultCryptoError;
use thiserror::Error;

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
