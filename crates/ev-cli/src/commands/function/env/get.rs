use clap::Parser;
use common::api::{
    client::ApiError,
    papi::{EvApi, EvApiClient},
    BasicAuth,
};
use thiserror::Error;

use crate::function::{resolve_function_by_name_or_pwd, ResolveFunctionError};

/// Get Function environment variables or a specific environment variable
#[derive(Parser, Debug)]
pub struct GetEnvArgs {
    #[arg(short, long)]
    /// The key of the environment variable to get. If not given, the entire environment will be retrieved
    pub key: Option<String>,
    #[arg(short, long)]
    /// The name of the function
    pub name: Option<String>,
}

#[derive(Error, Debug)]
pub enum GetEnvError {
    #[error(transparent)]
    Resolve(#[from] ResolveFunctionError),
    #[error("An error occurred while fetching the Function's environment: {0}")]
    ApiError(#[from] ApiError),
}

impl crate::CmdOutput for GetEnvError {
    fn code(&self) -> String {
        match self {
            GetEnvError::Resolve(_) => "functions/resolve-error",
            GetEnvError::ApiError(_) => "generic/api-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::SOFTWARE
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display, Debug)]
pub enum GetEnvMessage {
    #[strum(to_string = "Environment variable retrieved successfully.")]
    Success { value: serde_json::Value },
}

impl crate::CmdOutput for GetEnvMessage {
    fn code(&self) -> String {
        match self {
            GetEnvMessage::Success { .. } => "generic/success",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            GetEnvMessage::Success { value } => Some(value.clone()),
        }
    }
}

pub async fn run(args: GetEnvArgs, auth: BasicAuth) -> Result<GetEnvMessage, GetEnvError> {
    let api_client = EvApiClient::new(auth);

    let function = resolve_function_by_name_or_pwd(args.name, &api_client).await?;

    let result = match args.key {
        Some(key) => {
            api_client
                .get_function_environment_variable(&function, key)
                .await
        }
        None => api_client.get_function_environment(&function).await,
    }?;

    Ok(GetEnvMessage::Success {
        value: serde_json::json!(result),
    })
}
