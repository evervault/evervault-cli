use crate::{errors, CmdOutput};
use clap::Parser;
use common::api::{client::ApiError, papi::EvApiClient};
use common::api::{papi::EvApi, BasicAuth};
use serde_json::Value;
use std::str::FromStr;
use thiserror::Error;

/// Decrypt data using the Evervault API
#[derive(Debug, Parser)]
#[command(name = "decrypt", about)]
pub struct DecryptArgs {
    #[arg(long, num_args(0..))]
    /// The data to decrypt
    data: String,
}

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("An error occured while decrypting data: {0}")]
    ApiError(#[from] ApiError),
    #[error("Failed to serialize data: {0}")]
    Se(#[from] serde_json::Error),
}

impl CmdOutput for DecryptError {
    fn exitcode(&self) -> i32 {
        errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            DecryptError::ApiError(_) => "decrypt-api-error",
            DecryptError::Se(_) => "decrypt-serialization-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display)]
pub enum DecryptMessage {
    #[strum(to_string = "{value}")]
    Success { value: Value },
}

impl CmdOutput for DecryptMessage {
    fn exitcode(&self) -> i32 {
        errors::OK
    }

    fn code(&self) -> String {
        match self {
            DecryptMessage::Success { .. } => "decrypt-success",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            DecryptMessage::Success { value } => Some(value.clone()),
        }
    }
}

pub async fn run(args: DecryptArgs, auth: BasicAuth) -> Result<DecryptMessage, DecryptError> {
    let api_client = EvApiClient::new(auth);
    let decrypted = api_client.decrypt(Value::from_str(&args.data)?).await?;

    Ok(DecryptMessage::Success { value: decrypted })
}
