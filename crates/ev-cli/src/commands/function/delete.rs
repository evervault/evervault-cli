use std::io::IsTerminal;

use clap::Parser;
use common::api::{
    client::ApiError,
    papi::{self, EvApi},
    BasicAuth,
};
use thiserror::Error;

use crate::{
    commands::interact,
    function::{resolve_function_by_name_or_pwd, FunctionTomlError, ResolveFunctionError},
    CmdOutput,
};

/// Delete an existing Function
#[derive(Parser, Debug)]
pub struct DeleteArgs {
    #[arg(short, long, default_value = "false")]
    /// Force function deletion without confirmation
    force: bool,
    #[arg(short, long)]
    /// The name of the Function to delete
    name: Option<String>,
}

#[derive(strum_macros::Display, Debug)]
pub enum DeletePrompt {
    #[strum(to_string = "Are you sure you want to delete the Function '{function_name}'?")]
    AreYouSure { function_name: String },
}

#[derive(strum_macros::Display, Debug)]
pub enum DeleteMessage {
    #[strum(to_string = "Function deleted successfully.")]
    Success,
    #[strum(to_string = "Function deletion was cancelled.")]
    Cancelled,
}

impl CmdOutput for DeleteMessage {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn code(&self) -> String {
        match self {
            DeleteMessage::Success => "function-delete-success",
            DeleteMessage::Cancelled => "function-delete-cancelled",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    FunctionToml(#[from] FunctionTomlError),
    #[error(transparent)]
    Resolve(#[from] ResolveFunctionError),
    #[error("An error occurred while deleting the Function: {0}")]
    Api(#[from] ApiError),
    #[error(
        "The --force flag must be passed to the delete command when not running interactively."
    )]
    MustForce,
}

impl CmdOutput for DeleteError {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            DeleteError::Io(_) => "function-delete-io-error",
            DeleteError::FunctionToml(_) => "function-delete-toml-error",
            DeleteError::Resolve(_) => "function-delete-resolve-error",
            DeleteError::Api(_) => "function-delete-api-error",
            DeleteError::MustForce => "function-delete-must-force",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

pub async fn run(args: DeleteArgs, auth: BasicAuth) -> Result<DeleteMessage, DeleteError> {
    let api_client = papi::EvApiClient::new(auth);

    let target_function = resolve_function_by_name_or_pwd(args.name, &api_client).await?;

    if !args.force {
        if std::io::stdout().is_terminal() {
            let confirm = interact::confirm(
                DeletePrompt::AreYouSure {
                    function_name: target_function.clone().name,
                },
                false,
            );

            if !confirm {
                return Ok(DeleteMessage::Cancelled);
            }
        } else {
            return Err(DeleteError::MustForce);
        }
    }

    api_client.delete_function(&target_function).await?;

    Ok(DeleteMessage::Success)
}
