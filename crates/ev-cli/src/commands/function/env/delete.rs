use std::io::IsTerminal;

use clap::Parser;
use common::api::{
    client::{ApiError, ApiErrorKind},
    papi::{EvApi, EvApiClient},
    BasicAuth,
};
use thiserror::Error;

use crate::{
    commands::interact,
    function::{resolve_function_by_name_or_pwd, ResolveFunctionError},
};

/// Set an environment variable for a Function
#[derive(Parser, Debug)]
pub struct DeleteEnvArgs {
    #[arg(short, long)]
    /// The key of the environment variable to delete
    pub key: String,
    #[arg(short, long, default_value = "false")]
    /// Whether to force the deletion of the environment variable
    pub force: bool,
    #[arg(short, long)]
    /// The name of the function
    pub name: Option<String>,
}

#[derive(Error, Debug)]
pub enum DeleteEnvError {
    #[error(transparent)]
    Resolve(#[from] ResolveFunctionError),
    #[error("An error occured while deleting the environment variable: {0}")]
    ApiError(#[from] ApiError),
    #[error("The environment variable with key \"{0}\" doesn't exist. Use the env get command to see a list of your functions environment variables.")]
    NotFound(String),
    #[error("Environment variable deletion aborted.")]
    Aborted,
    #[error(
        "The --force flag must be passed to the env delete command when not running interactively."
    )]
    MustForce,
}

impl crate::CmdOutput for DeleteEnvError {
    fn code(&self) -> String {
        match self {
            DeleteEnvError::Resolve(_) => "function-resolve-error",
            DeleteEnvError::ApiError(_) => "function-environment-delete-error",
            DeleteEnvError::NotFound(_) => "function-env-var-not-found",
            DeleteEnvError::Aborted => "function-env-var-delete-aborted",
            DeleteEnvError::MustForce => "function-env-var-delete-must-force",
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
pub enum DeleteEnvMessage {
    #[strum(to_string = "Function environment variable deleted successfully.")]
    Success { value: serde_json::Value },
}

#[derive(strum_macros::Display, Debug)]
pub enum DeleteEnvPrompt {
    #[strum(to_string = "Are you sure you want to delete the environment variable?")]
    Confirm,
}

impl crate::CmdOutput for DeleteEnvMessage {
    fn code(&self) -> String {
        match self {
            DeleteEnvMessage::Success { .. } => "function-env-var-delete-success",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            DeleteEnvMessage::Success { value } => Some(value.clone()),
        }
    }
}

pub async fn run(args: DeleteEnvArgs, auth: BasicAuth) -> Result<DeleteEnvMessage, DeleteEnvError> {
    let api_client = EvApiClient::new(auth);

    let function = resolve_function_by_name_or_pwd(args.name, &api_client).await?;

    if !args.force {
        let confirmed = if std::io::stdout().is_terminal() {
            interact::confirm(DeleteEnvPrompt::Confirm, false)
        } else {
            return Err(DeleteEnvError::MustForce);
        };

        if !confirmed {
            return Err(DeleteEnvError::Aborted);
        }
    }

    let updated_function = api_client
        .delete_function_environment_variable(&function, &args.key)
        .await
        .map_err(|err| match err.kind {
            ApiErrorKind::NotFound => DeleteEnvError::NotFound(args.key.clone()),
            _ => err.into(),
        })?;

    Ok(DeleteEnvMessage::Success {
        value: serde_json::json!({
            "environment": updated_function.environment_variables
        }),
    })
}
