use clap::{ArgAction, Parser};
use common::api::{
    client::ApiError,
    papi::{self, EvApi},
    BasicAuth,
};
use serde_json::Value;
use std::str::FromStr;
use thiserror::Error;

use crate::{
    function::{resolve_function_by_name_or_pwd, FunctionTomlError, ResolveFunctionError},
    CmdOutput,
};

/// Run a Function
#[derive(Parser, Debug)]
pub struct RunArgs {
    #[arg(short, long)]
    /// The name of the Function to run
    name: Option<String>,
    #[arg(short, long)]
    /// The JSON payload to send to the Function
    data: Option<String>,
    #[arg(long = "async", short = 'a', action=ArgAction::SetTrue)]
    /// If the Function should be run asynchronously
    is_async: bool,
}

#[derive(strum_macros::Display, Debug)]
pub enum RunPrompt {}

#[derive(strum_macros::Display, Debug)]
pub enum RunMessage {
    #[strum(to_string = "Function ran sucessfully")]
    Success { result: Value },
    #[strum(to_string = "Function scheduled for async run")]
    SuccessAsync { result: Value },
}

impl CmdOutput for RunMessage {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn code(&self) -> String {
        match self {
            RunMessage::Success { .. } => "function-run-success",
            RunMessage::SuccessAsync { .. } => "function-scheduled-async-success",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            RunMessage::Success { result } => Some(result.clone()),
            RunMessage::SuccessAsync { result } => Some(result.clone()),
        }
    }
}

#[derive(Error, Debug)]
pub enum RunError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    FunctionToml(#[from] FunctionTomlError),
    #[error(transparent)]
    Resolve(#[from] ResolveFunctionError),
    #[error("An error occurred while running the Function: {0}")]
    Api(#[from] ApiError),
    #[error("Failed to parse provided data to JSON: {0}")]
    Se(#[from] serde_json::Error),
}

impl CmdOutput for RunError {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            RunError::Io(_) => "function-run-io-error",
            RunError::FunctionToml(_) => "function-run-toml-error",
            RunError::Resolve(_) => "function-run-resolve-error",
            RunError::Api(_) => "function-run-api-error",
            RunError::Se(_) => "function-run-json-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

pub async fn run(args: RunArgs, auth: BasicAuth) -> Result<RunMessage, RunError> {
    let api_client = papi::EvApiClient::new(auth);

    let function = resolve_function_by_name_or_pwd(args.name, &api_client).await?;

    let result = api_client
        .run_function(
            &function,
            args.data
                .and_then(|data| Some(Value::from_str(&data)))
                .transpose()?,
            args.is_async,
        )
        .await?;

    if args.is_async {
        Ok(RunMessage::SuccessAsync { result })
    } else {
        Ok(RunMessage::Success { result })
    }
}
