use std::path::PathBuf;

use clap::{ArgGroup, Parser};
use common::api::{
    client::ApiError,
    papi::{self, EvApi},
    BasicAuth,
};
use thiserror::Error;

use crate::{
    commands::interact,
    function::{FunctionToml, FunctionTomlError},
    BaseArgs, CmdOutput,
};

/// Delete an existing Function
#[derive(Parser, Debug)]
#[clap(group(
  ArgGroup::new("json-path")
    .arg("json")
    .requires("path")
))]
pub struct DeleteArgs {
    #[arg(short, long)]
    /// The path to the toml of the Function to delete
    path: Option<String>,
}

#[derive(strum_macros::Display, Debug)]
pub enum DeletePrompt {
    #[strum(to_string = "Select the Function you want to delete:")]
    Name,
}

#[derive(strum_macros::Display, Debug)]
pub enum DeleteMessage {
    Success,
}

impl CmdOutput for DeleteMessage {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn code(&self) -> String {
        "function-delete-success".to_string()
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
        }
        .to_string()
    }
}

pub async fn run(args: DeleteArgs, auth: BasicAuth) -> Result<DeleteMessage, DeleteError> {
    let api_client = papi::EvApiClient::new(auth);
    let base_args = BaseArgs::parse();

    let functions = api_client.get_all_functions_for_app().await.unwrap();

    let maybe_target_function = match args.path {
        Some(p) => {
            let path = PathBuf::from(p);
            let func_toml = FunctionToml::try_from(&path)?;

            functions.iter().find(|f| f.name == func_toml.function.name)
        }
        None if base_args.json => unreachable!("Infallible over arg group"),
        None => {
            let function_names = functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>();
            let selected =
                interact::select(&function_names, 0, DeletePrompt::Name).expect("No input given");
            functions.get(selected)
        }
    };

    let target_function = maybe_target_function.ok_or_else(|| DeleteError::FunctionNotFound)?;

    api_client.delete_function(&target_function).await?;

    Ok(DeleteMessage::Success)
}
