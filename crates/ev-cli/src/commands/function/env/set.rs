use clap::Parser;
use common::api::{
    client::ApiError,
    papi::{EvApi, EvApiClient},
    BasicAuth,
};
use thiserror::Error;

use crate::function::{resolve_function_by_name_or_pwd, ResolveFunctionError};

/// Set an environment variable for a Function
#[derive(Parser, Debug)]
pub struct SetEnvArgs {
    #[arg(short, long)]
    /// The key of the environment variable to set
    pub key: String,
    #[arg(long)]
    /// The value of the environment variable to set
    pub value: String,
    #[arg(short, long, default_value = "false")]
    /// Whether the environment variable is secret
    pub secret: bool,
    #[arg(short, long)]
    /// The name of the function
    pub name: Option<String>,
}

#[derive(Error, Debug)]
pub enum SetEnvError {
    #[error(transparent)]
    Resolve(#[from] ResolveFunctionError),
    #[error("An error occured while setting the environment variable: {0}")]
    ApiError(#[from] ApiError),
    #[error("The environment variable with key \"{0}\" already exists. Use the env delete command to remove it first.")]
    AlreadyExists(String),
}

impl crate::CmdOutput for SetEnvError {
    fn code(&self) -> String {
        match self {
            SetEnvError::Resolve(_) => "functions/resolve-error",
            SetEnvError::ApiError(_) => "generic/api-error",
            SetEnvError::AlreadyExists(_) => "generic/already-exists",
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
pub enum SetEnvMessage {
    #[strum(to_string = "Function environment variable set successfully.")]
    Success { value: serde_json::Value },
}

impl crate::CmdOutput for SetEnvMessage {
    fn code(&self) -> String {
        match self {
            SetEnvMessage::Success { .. } => "generic/success",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            SetEnvMessage::Success { value } => Some(value.clone()),
        }
    }
}

pub async fn run(args: SetEnvArgs, auth: BasicAuth) -> Result<SetEnvMessage, SetEnvError> {
    let api_client = EvApiClient::new(auth);

    let function = resolve_function_by_name_or_pwd(args.name, &api_client).await?;
    let env_vars = api_client.get_function_environment(&function).await?;

    if env_vars.contains_key(&args.key) {
        return Err(SetEnvError::AlreadyExists(args.key));
    }

    let updated_function = api_client
        .set_function_environment_variable(&function, args.key, args.value, args.secret)
        .await?;

    Ok(SetEnvMessage::Success {
        value: serde_json::json!({
            "environment": updated_function.environment_variables
        }),
    })
}
