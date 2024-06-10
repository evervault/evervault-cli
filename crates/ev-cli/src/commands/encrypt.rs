use crate::{errors, CmdOutput};
use clap::Parser;
use common::api::{client::ApiError, papi::EvApiClient};
use common::api::{papi::EvApi, BasicAuth};
use serde_json::Value;
use std::str::FromStr;
use thiserror::Error;

/// Encrypt data using the Evervault API
#[derive(Debug, Parser)]
#[command(name = "encrypt", about)]
pub struct EncryptArgs {
    #[arg(short, long, num_args(0..))]
    /// The data to encrypt
    data: String,
}

#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("An error occured while encrypting data: {0}")]
    ApiError(#[from] ApiError),
    #[error("Failed to serialize data: {0}")]
    Se(#[from] serde_json::Error),
}

impl CmdOutput for EncryptError {
    fn exitcode(&self) -> i32 {
        errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            EncryptError::ApiError(_) => "generic/api-error",
            EncryptError::Se(_) => "generic/serialization-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display)]
pub enum EncryptMessage {
    #[strum(to_string = "")]
    Success { value: Value },
}

impl CmdOutput for EncryptMessage {
    fn exitcode(&self) -> i32 {
        errors::OK
    }

    fn code(&self) -> String {
        match self {
            EncryptMessage::Success { .. } => "generic/success",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            EncryptMessage::Success { value } => Some(value.clone()),
        }
    }
}

pub async fn run(args: EncryptArgs, auth: BasicAuth) -> Result<EncryptMessage, EncryptError> {
    let api_client = EvApiClient::new(auth);

    let data = match Value::from_str(&args.data) {
        Ok(val) => val,
        Err(_) => Value::String(args.data),
    };

    let encrypted = api_client.encrypt(data).await?;

    Ok(EncryptMessage::Success { value: encrypted })
}
