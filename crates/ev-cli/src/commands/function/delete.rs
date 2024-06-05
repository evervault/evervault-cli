use std::io::IsTerminal;

use clap::Parser;
use common::api::{
    client::ApiError,
    papi::{self, EvApi},
    BasicAuth,
};
use thiserror::Error;

use crate::{commands::interact, function::FunctionTomlError, CmdOutput};

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
    #[strum(to_string = "Select the Function you want to delete:")]
    Name,
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
}

#[derive(Error, Debug)]
pub enum DeleteError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    FunctionToml(#[from] FunctionTomlError),
    #[error(
        "The specified Function could not be found. Please check the Function name and try again."
    )]
    FunctionNotFound,
    #[error("An error occurred while deleting the Function: {0}")]
    Api(#[from] ApiError),
    #[error(
        "The --force flag must be passed to the delete command when not running interactively."
    )]
    MustForce,
    #[error("You must provide a Function name to delete when not running interactively.")]
    MustProvideName,
}

impl CmdOutput for DeleteError {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            DeleteError::Io(_) => "function-delete-io-error",
            DeleteError::FunctionToml(_) => "function-delete-toml-error",
            DeleteError::FunctionNotFound => "function-delete-not-found",
            DeleteError::Api(_) => "function-delete-api-error",
            DeleteError::MustForce => "function-delete-must-force",
            DeleteError::MustProvideName => "function-delete-must-provide-name",
        }
        .to_string()
    }
}

pub async fn run(args: DeleteArgs, auth: BasicAuth) -> Result<DeleteMessage, DeleteError> {
    let api_client = papi::EvApiClient::new(auth);

    let functions = api_client.get_all_functions_for_app().await.unwrap();

    let is_terminal = std::io::stdout().is_terminal();

    let maybe_target_function = match args.name {
        Some(n) => functions.iter().find(|f| f.name == n),
        None if !is_terminal => return Err(DeleteError::MustProvideName),
        None => {
            let function_names = functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>();
            let selected =
                interact::select(&function_names, 0, DeletePrompt::Name).expect("No input given");
            functions.get(selected)
        }
    };

    let target_function = maybe_target_function.ok_or_else(|| DeleteError::FunctionNotFound)?;

    if !args.force {
        if is_terminal {
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
